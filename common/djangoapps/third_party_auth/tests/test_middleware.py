"""
Tests for third party auth middleware
"""


import json
from unittest import mock

import ddt
from django.contrib.messages.middleware import MessageMiddleware
from django.http import HttpResponse
from django.test.client import RequestFactory
from requests.exceptions import HTTPError
from social_core import exceptions as social_exceptions

from openedx.core.djangolib.testing.utils import skip_unless_lms
from common.djangoapps.student.helpers import get_next_url_for_login_page
from common.djangoapps.third_party_auth import pipeline
from common.djangoapps.third_party_auth.middleware import (
    DUPLICATE_PROVIDER_ID_SESSION_KEY,
    ExceptionMiddleware,
    get_failed_provider_id,
)
from common.djangoapps.third_party_auth.saml import SAMLAuthBackend
from common.djangoapps.third_party_auth.tests.testutil import TestCase


class ThirdPartyAuthMiddlewareTestCase(TestCase):
    """Tests that ExceptionMiddleware is correctly redirected"""

    @skip_unless_lms
    @mock.patch('django.conf.settings.MESSAGE_STORAGE', 'django.contrib.messages.storage.cookie.CookieStorage')
    def test_http_exception_redirection(self):
        """
        Test ExceptionMiddleware is correctly redirected to login page
        when PSA raises HttpError exception.
        """

        request = RequestFactory().get("dummy_url")
        next_url = get_next_url_for_login_page(request)
        login_url = '/login?next=' + next_url
        request.META['HTTP_REFERER'] = 'http://example.com:8000/login'
        exception = HTTPError()
        exception.response = HttpResponse(status=502)

        # Add error message for error in auth pipeline
        MessageMiddleware(get_response=lambda request: None).process_request(request)
        response = ExceptionMiddleware(get_response=lambda request: None).process_exception(
            request, exception
        )
        target_url = response.url

        assert response.status_code == 302
        assert target_url.endswith(login_url)


@ddt.ddt
class ExceptionMiddlewareAccountSettingsDispatchTestCase(TestCase):
    """
    Tests that ExceptionMiddleware.get_redirect_uri() dispatches to the URL
    registered in AUTH_DISPATCH_URLS for the current auth_entry, and that it
    no longer needs to duplicate the error message in a custom session key:
    SocialAuthExceptionMiddleware.process_exception (the parent class)
    already leaves it in the Django messages framework for any
    SocialAuthBaseException, tagged 'social-auth <backend name>'. The
    Account MFE reads that message via
    openedx.core.djangoapps.user_api.views.ThirdPartyAuthErrorMessageView.
    """

    def _build_request(self, auth_entry=pipeline.AUTH_ENTRY_ACCOUNT_SETTINGS):
        """Build a fake request with session and backend for testing TPA error handling."""
        request = RequestFactory().get('/auth/login/tpa-saml/')
        request.session = {}
        request.session[pipeline.AUTH_ENTRY_KEY] = auth_entry

        class FakeBackend:
            name = 'tpa-saml'

        request.backend = FakeBackend()
        request.social_strategy = mock.MagicMock()
        request.social_strategy.setting.return_value = None
        return request

    @ddt.data(
        social_exceptions.AuthAlreadyAssociated,
        social_exceptions.AuthCanceled,
        social_exceptions.AuthFailed,
        social_exceptions.AuthTokenError,
        social_exceptions.AuthStateMissing,
        social_exceptions.AuthStateForbidden,
        social_exceptions.AuthTokenRevoked,
        social_exceptions.AuthUnreachableProvider,
        social_exceptions.InvalidEmail,
    )
    def test_dispatches_to_account_settings_url_for_any_tpa_exception(self, exception_class):
        """The redirect target is /account/settings for the account_settings flow, regardless of exception type."""
        request = self._build_request()

        redirect_uri = ExceptionMiddleware(get_response=lambda r: None).get_redirect_uri(
            request, exception_class('tpa-saml')
        )

        assert redirect_uri == pipeline.AUTH_DISPATCH_URLS[pipeline.AUTH_ENTRY_ACCOUNT_SETTINGS]

    def test_dispatches_elsewhere_outside_account_settings_entry(self):
        """AUTH_DISPATCH_URLS is keyed by auth_entry, not by exception type."""
        request = self._build_request(auth_entry=pipeline.AUTH_ENTRY_LOGIN)

        redirect_uri = ExceptionMiddleware(get_response=lambda r: None).get_redirect_uri(
            request, social_exceptions.AuthAlreadyAssociated('tpa-saml')
        )

        assert redirect_uri == pipeline.AUTH_DISPATCH_URLS[pipeline.AUTH_ENTRY_LOGIN]

    @skip_unless_lms
    @ddt.data(
        social_exceptions.AuthAlreadyAssociated,
        social_exceptions.AuthCanceled,
        social_exceptions.AuthFailed,
        social_exceptions.AuthTokenError,
        social_exceptions.AuthStateMissing,
        social_exceptions.AuthStateForbidden,
        social_exceptions.AuthTokenRevoked,
        social_exceptions.AuthUnreachableProvider,
    )
    def test_process_exception_leaves_social_auth_tagged_message_for_mfe(self, exception_class):
        """
        End to end: process_exception (the parent implementation) must still
        queue a Django message tagged with 'social-auth' for the Account MFE
        to read, since we no longer save it ourselves. Covers every
        recognized third-party-auth exception, not just AuthAlreadyAssociated.
        """
        request = self._build_request()
        MessageMiddleware(get_response=lambda request: None).process_request(request)
        exception = exception_class('tpa-saml')

        ExceptionMiddleware(get_response=lambda r: None).process_exception(request, exception)

        queued_messages = list(request._messages)  # pylint: disable=protected-access
        assert len(queued_messages) == 1
        assert queued_messages[0].extra_tags.split() == ['social-auth', 'tpa-saml']
        assert str(queued_messages[0]) == str(exception)

    @skip_unless_lms
    def test_process_exception_does_not_queue_message_for_unrecognized_exception(self):
        """
        Non-SocialAuthBaseException errors are untouched by
        SocialAuthExceptionMiddleware.process_exception -- confirms we're not
        accidentally tagging unrelated exceptions as TPA errors.
        """
        request = self._build_request()
        MessageMiddleware(get_response=lambda request: None).process_request(request)

        result = ExceptionMiddleware(get_response=lambda r: None).process_exception(request, ValueError('boom'))

        assert result is None
        assert not list(request._messages)  # pylint: disable=protected-access


@skip_unless_lms
@ddt.ddt
class DuplicateProviderIdTestCase(TestCase):
    """
    NAU: tests that ExceptionMiddleware saves in the session which provider failed with AuthAlreadyAssociated, so
    the Account MFE message can name it. NAU has two SAML IdPs that share the "tpa-saml" backend.
    """

    def setUp(self):
        super().setUp()
        self.enable_saml()
        self.configure_saml_provider(enabled=True, slug='cccmd', name='Cartão de Cidadão', entity_id='https://cccmd')
        self.configure_saml_provider(enabled=True, slug='rctsaai', name='RCTSaai', entity_id='https://rctsaai')
        self.configure_google_provider(enabled=True)

    @staticmethod
    def _saml_request(relay_state):
        """Build a request that failed on the SAML backend with the given RelayState (None for no RelayState)."""
        request = RequestFactory().post('/auth/complete/tpa-saml/')
        request.session = {}
        # strategy is set in SAMLAuthBackend.__init__, so it isn't in the spec
        request.backend = mock.MagicMock(spec=SAMLAuthBackend, strategy=mock.MagicMock())
        request.backend.name = 'tpa-saml'
        request.backend.strategy.request_data.return_value = {} if relay_state is None else {'RelayState': relay_state}
        return request

    @staticmethod
    def _oauth_request(backend_name):
        """Build a request that failed on the given OAuth2 backend."""
        request = RequestFactory().get(f'/auth/complete/{backend_name}/')
        request.session = {}
        request.backend = mock.Mock(spec=['name'])
        request.backend.name = backend_name
        return request

    @ddt.data(
        (json.dumps({'idp': 'cccmd', 'next': '/account/settings'}), 'saml-cccmd'),
        (json.dumps({'idp': 'rctsaai', 'next': None}), 'saml-rctsaai'),
        ('rctsaai', 'saml-rctsaai'),  # RelayState with just the IdP name, as in previous versions
        (json.dumps({'idp': 'unknown'}), None),
        (json.dumps({'next': '/account/settings'}), None),
        (None, None),
    )
    @ddt.unpack
    def test_saml_provider_is_told_by_relay_state(self, relay_state, expected_provider_id):
        assert get_failed_provider_id(self._saml_request(relay_state)) == expected_provider_id

    def test_oauth_provider_is_told_by_backend(self):
        assert get_failed_provider_id(self._oauth_request('google-oauth2')) == 'oa2-google-oauth2'

    def test_no_provider_for_unconfigured_backend(self):
        assert get_failed_provider_id(self._oauth_request('facebook')) is None

    def test_no_provider_without_backend(self):
        assert get_failed_provider_id(RequestFactory().get('/')) is None

    def _process_exception(self, request, exception):
        """Run ExceptionMiddleware.process_exception the way Django does, with the messages framework enabled."""
        request.social_strategy = mock.MagicMock()
        request.social_strategy.setting.return_value = None
        request.session[pipeline.AUTH_ENTRY_KEY] = pipeline.AUTH_ENTRY_ACCOUNT_SETTINGS
        MessageMiddleware(get_response=lambda r: None).process_request(request)
        return ExceptionMiddleware(get_response=lambda r: None).process_exception(request, exception)

    def test_already_associated_saves_the_provider(self):
        request = self._saml_request(json.dumps({'idp': 'cccmd'}))

        self._process_exception(request, social_exceptions.AuthAlreadyAssociated(request.backend))

        assert request.session[DUPLICATE_PROVIDER_ID_SESSION_KEY] == 'saml-cccmd'
        assert [str(message) for message in request._messages] == [  # pylint: disable=protected-access
            'This account is already in use.'
        ]

    def test_other_errors_do_not_save_a_provider(self):
        request = self._oauth_request('google-oauth2')

        self._process_exception(request, social_exceptions.AuthForbidden(request.backend))

        assert DUPLICATE_PROVIDER_ID_SESSION_KEY not in request.session

    def test_provider_of_a_previous_error_is_removed_when_it_cant_be_told(self):
        request = self._oauth_request('facebook')
        request.session[DUPLICATE_PROVIDER_ID_SESSION_KEY] = 'saml-cccmd'

        self._process_exception(request, social_exceptions.AuthAlreadyAssociated(request.backend))

        assert DUPLICATE_PROVIDER_ID_SESSION_KEY not in request.session

    def test_failure_telling_the_provider_does_not_break_error_handling(self):
        request = self._oauth_request('google-oauth2')

        with mock.patch(
            'common.djangoapps.third_party_auth.middleware.get_failed_provider_id', side_effect=Exception('boom')
        ):
            response = self._process_exception(request, social_exceptions.AuthAlreadyAssociated(request.backend))

        assert response.status_code == 302
        assert DUPLICATE_PROVIDER_ID_SESSION_KEY not in request.session
        assert len(list(request._messages)) == 1  # pylint: disable=protected-access
