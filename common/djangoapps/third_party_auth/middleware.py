"""Middleware classes for third_party_auth."""


import json
import logging

import six.moves.urllib.parse
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext as _
from requests import HTTPError
from social_core.exceptions import AuthAlreadyAssociated
from social_django.middleware import SocialAuthExceptionMiddleware

from common.djangoapps.student.helpers import get_next_url_for_login_page

from . import pipeline, provider
from .saml import SAMLAuthBackend

log = logging.getLogger(__name__)

# NAU: provider_id (e.g. "saml-cccmd" or "oa2-google-oauth2") of the provider whose account could not be linked
# because it is already linked to another user (AuthAlreadyAssociated). The Django message left by
# SocialAuthExceptionMiddleware only carries the backend name, which several SAML IdPs share ("tpa-saml"), so the
# provider is saved here while the request that failed still has it. It is read, and removed, by
# openedx.core.djangoapps.user_api.views.ThirdPartyAuthErrorMessageView to name the provider in the message.
DUPLICATE_PROVIDER_ID_SESSION_KEY = 'nau_tpa_duplicate_provider_id'


def get_failed_provider_id(request):
    """
    NAU: returns the provider_id of the provider used in the failed request, or None if it can't be told.

    A SAML IdP is told by the "idp" in the RelayState, as SAMLAuthBackend reads it in auth_complete: a JSON object,
    or just the IdP name in older versions. An OAuth2 provider is told by its backend, if only one enabled provider
    uses it.
    """
    backend = getattr(request, 'backend', None)
    if backend is None:
        return None

    if isinstance(backend, SAMLAuthBackend):
        relay_state = backend.strategy.request_data().get('RelayState')
        if not relay_state:
            return None
        try:
            idp_name = json.loads(relay_state)['idp']
        except (ValueError, TypeError, KeyError):
            idp_name = relay_state
        saml_provider = provider.Registry.get(f'saml-{idp_name}')
        return saml_provider.provider_id if saml_provider else None

    providers = list(provider.Registry.get_enabled_by_backend_name(backend.name))
    return providers[0].provider_id if len(providers) == 1 else None


class ExceptionMiddleware(SocialAuthExceptionMiddleware, MiddlewareMixin):
    """Custom middleware that handles conditional redirection."""

    def get_redirect_uri(self, request, exception):
        # Fall back to django settings's SOCIAL_AUTH_LOGIN_ERROR_URL.
        redirect_uri = super().get_redirect_uri(request, exception)

        # Safe because it's already been validated by
        # pipeline.parse_query_params. If that pipeline step ever moves later
        # in the pipeline stack, we'd need to validate this value because it
        # would be an injection point for attacker data.
        auth_entry = request.session.get(pipeline.AUTH_ENTRY_KEY)

        # Check if we have an auth entry key we can use instead
        if auth_entry and auth_entry in pipeline.AUTH_DISPATCH_URLS:
            redirect_uri = pipeline.AUTH_DISPATCH_URLS[auth_entry]

        return redirect_uri

    def process_exception(self, request, exception):
        """Handles specific exception raised by Python Social Auth eg HTTPError."""

        referer_url = request.META.get('HTTP_REFERER', '')
        if (referer_url and isinstance(exception, HTTPError) and
                exception.response.status_code == 502):
            referer_url = six.moves.urllib.parse.urlparse(referer_url).path
            if referer_url == reverse('signin_user'):
                messages.error(request, _('Unable to connect with the external provider, please try again'),
                               extra_tags='social-auth')

                redirect_url = get_next_url_for_login_page(request)
                return redirect('/login?next=' + redirect_url)

        if isinstance(exception, AuthAlreadyAssociated):
            self._save_duplicate_provider_id(request)

        return super().process_exception(request, exception)

    @staticmethod
    def _save_duplicate_provider_id(request):
        """
        NAU: saves the provider of an AuthAlreadyAssociated error in the session, see DUPLICATE_PROVIDER_ID_SESSION_KEY.

        A failure here must never get in the way of handling the original error, so it is only logged.
        """
        session = getattr(request, 'session', None)
        if session is None:
            return
        try:
            provider_id = get_failed_provider_id(request)
        except Exception:  # pylint: disable=broad-except
            log.exception('Could not tell the third party auth provider of an AuthAlreadyAssociated error')
            provider_id = None

        if provider_id:
            session[DUPLICATE_PROVIDER_ID_SESSION_KEY] = provider_id
        else:
            session.pop(DUPLICATE_PROVIDER_ID_SESSION_KEY, None)
