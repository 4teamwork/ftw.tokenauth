from AccessControl.requestmethod import postonly
from AccessControl.SecurityInfo import ClassSecurityInfo
from datetime import datetime
from datetime import timedelta
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.service_keys.key_generation import create_service_key_pair
from logging import getLogger
from plone import api
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin  # noqa
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from zope.component.hooks import getSite
from zope.globalrequest import getRequest
from zope.interface import implements
import base64
import json
import os


DEFAULT_TOKEN_LIFETIME = 3600

log = getLogger(__name__)


manage_addTokenAuthenticationPlugin = PageTemplateFile(
    "www/addPlugin", globals(), __name__="manage_addTokenAuthenticationPlugin")


def addTokenAuthenticationPlugin(self, id_, title=None,
                                 access_token_lifetime=None, REQUEST=None):
    """Add a token authentication plugin
    """
    plugin = TokenAuthenticationPlugin(id_, title, access_token_lifetime)
    self._setObject(plugin.getId(), plugin)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace"
            "?manage_tabs_message=token+authentication+plugin+added." %
            self.absolute_url()
        )


class TokenAuthenticationPlugin(BasePlugin):
    """PAS Plugin that authenticates requests based on OAuth2 Bearer tokens.

    Those tokens are issued by the @@oauth2-token endpoint in exchange for
    a JWT authorization grant, and stored in a storage on this Plugin.
    """

    implements(
        IAuthenticationPlugin,
        IExtractionPlugin,
    )
    meta_type = "Token Authentication Plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},) +
        BasePlugin.manage_options
    )
    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    def __init__(self, id_, title=None, access_token_lifetime=None):
        self._setId(id_)
        self.title = title

        self.access_token_lifetime = DEFAULT_TOKEN_LIFETIME
        if access_token_lifetime:
            self.access_token_lifetime = int(access_token_lifetime)

        # Initialize storage
        CredentialStorage(self)

    def get_token_uri(self):
        """Return URI of the OAuth2 token endpoint.

        This is the URI where the client can exchange a JWT authorization
        grant for an access token, and must also be the audience claim in
        the JWT grant.
        """
        portal = api.portal.get()
        return portal.absolute_url() + '/@@oauth2-token'

    security.declarePrivate('issue_access_token')

    def issue_access_token(self, key_id):
        """Create and store an access token tied to key_id.
        """
        storage = CredentialStorage(self)

        token = self._create_access_token()
        while storage.contains_access_token(token):
            # Make sure we produce a globally unique access token. Unlikely
            # a collision would happen with 64 random bytes, but we wouldn't
            # want to overwrite people's existing tokens
            token = self._create_access_token()

        access_token = {
            'token': token,
            'issued': datetime.now(),
            'expires_in': self.access_token_lifetime,
            'key_id': key_id,
        }

        storage.add_access_token(access_token)
        storage.clean_up_expired_tokens()
        return access_token

    def is_expired(self, access_token):
        """Check whether a token is expired.
        """
        # TODO: Allow for clock skew
        issued = access_token['issued']
        expires_in = access_token['expires_in']
        expires = issued + timedelta(seconds=expires_in)

        if expires < datetime.now():
            return True

        return False

    def _create_access_token(self):
        """Produce a raw access token (opaque string).

        We use 64 random bytes from a CSPRNG and urlsafe-b64 encode them.

        See RFC 6749 (1.4.  Access Token) for (some) details on access
        tokens in OAuth2:
        https://tools.ietf.org/html/rfc6749#section-1.4
        """
        return base64.urlsafe_b64encode(os.urandom(64))

    security.declarePrivate('issue_keypair')

    def issue_keypair(self, user_id, title):
        token_uri = self.get_token_uri()
        private_key, service_key = create_service_key_pair(
            user_id, title, token_uri)

        storage = CredentialStorage(self)
        storage.add_service_key(service_key)
        return private_key, service_key

    security.declarePrivate('extractCredentials')

    def extractCredentials(self, request):
        """Extract an OAuth2 bearer access token from the request.

        Implementation of IExtractionPlugin that extracts any 'Bearer' token
        from the HTTP 'Authorization' header.
        """
        # See RFC 6750 (2.1. Authorization Request Header Field) for details
        # on bearer token usage in OAuth2
        # https://tools.ietf.org/html/rfc6750#section-2.1

        creds = {}
        auth = request._auth
        if auth is None:
            return None
        if auth[:7].lower() == 'bearer ':
            creds['access_token'] = auth.split()[-1]
        else:
            return None

        return creds

    security.declarePrivate('authenticateCredentials')

    def authenticateCredentials(self, credentials):
        """Authenticate a request that contains an OAuth2 bearer access token.

        Implementation of IAuthenticationPlugin that authenticates requests
        that contain a valid OAuth2 bearer access token.

        """
        # Ignore credentials that are not from our extractor
        extractor = credentials.get('extractor')
        if extractor != self.getId():
            # While RFC 6750 says that requests without authentication MUST
            # be answered with a WWW-Authenticate challenge, we can't do that
            # here, since OAuth2 isn't the only authentication mechanism we
            # need to support.
            # See: https://tools.ietf.org/html/rfc6750#section-3
            return None

        received_token = credentials['access_token']
        storage = CredentialStorage(self)

        # Reject unknown or revoked tokens
        if not storage.contains_access_token(received_token):
            # TODO: Should we send an 'invalid_token' error response here?
            return None

        stored_access_token = storage.get_access_token(received_token)

        # Reject expired tokens
        if self.is_expired(stored_access_token):
            # Token expired, send error response according to
            # https://tools.ietf.org/html/rfc6750#section-3.1
            response = getRequest().response
            body = json.dumps({'error': 'invalid_token',
                               'error_description': 'Access token expired'})
            response.setBody(body, lock=True)
            response.setStatus(401, lock=True)

            # TODO: According to RFC 6750, we should also send a
            # WWW-Authenticate: Bearer realm="example"
            # here. Check whether we really want to send this challenge
            return None

        # Fetch service key that the token was tied to (by us)
        service_key = storage.get_service_key(stored_access_token['key_id'])

        # Fetch and verify the user associated with the service_key
        user_id = service_key['user_id']
        pas = self._getPAS()
        # This only works for users in Plone site, not Zope application root
        info = pas._verifyUser(pas.plugins, user_id=user_id)
        if info is None:
            return None

        mtool = getToolByName(getSite(), 'portal_membership')
        member = mtool.getMemberById(user_id)
        if member is None:
            return None

        return user_id, user_id

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of Token Authentication Plugin.
        """
        response = REQUEST.response

        self.access_token_lifetime = int(REQUEST.form.get(
            'access_token_lifetime', DEFAULT_TOKEN_LIFETIME))

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))
