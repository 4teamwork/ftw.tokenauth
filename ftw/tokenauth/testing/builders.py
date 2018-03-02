from ftw.builder import Builder
from ftw.builder import builder_registry
from ftw.builder import create
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.service_keys.key_generation import create_service_key_pair
from ftw.tokenauth.testing.layers import DEFAULT_TESTING_TOKEN_URI
from plone.app.testing import TEST_USER_ID
from zope.component.hooks import getSite
import jwt
import time


class ServiceKeyBuilder(object):
    """Creates a service_key (public) that is persisted in the storage.

    The private key is discarded. This builder can be used for tests where
    persistence of the service_key is required, but the private key is not.
    """

    def __init__(self, session):
        self.session = session
        self.portal = getSite()
        self.plugin = self.portal.acl_users['token_auth']
        self.arguments = {
            'user_id': TEST_USER_ID,
            'title': 'Key Title',
        }

    def having(self, **kwargs):
        self.arguments.update(kwargs)
        return self

    def create(self, **kwargs):
        private_key, service_key = self.plugin.issue_keypair(
            self.arguments.get('user_id'),
            self.arguments.get('title'),
            self.arguments.get('ip_range'))

        return service_key

builder_registry.register('service_key', ServiceKeyBuilder)


class KeyPairBuilder(object):
    """Creates a key pair consisting of private_key and service_key.

    The service_key is NOT persisted in storage, so this builder can be used
    in unit tests (no dependency on Plone at all), and for tests that require
    the use of both the private and the public keys (like signing JWTs).

    On the other hand, it obviously can't be used in tests where persistence
    of the service_key in storage is required.
    """

    def __init__(self, session):
        self.session = session
        self.arguments = {
            'user_id': 'default-user-id',
            'client_id': 'default-client-id',
            'title': 'Test Key',
            'token_uri': DEFAULT_TESTING_TOKEN_URI,
        }

    def having(self, **kwargs):
        self.arguments.update(kwargs)
        return self

    def create(self, **kwargs):
        private_key, service_key = create_service_key_pair(
            self.arguments.get('user_id'),
            self.arguments.get('title'),
            self.arguments.get('token_uri'),
            self.arguments.get('ip_range'),
        )
        # Override the randomly created client_id
        service_key['client_id'] = self.arguments.get('client_id')

        return private_key, service_key

builder_registry.register('keypair', KeyPairBuilder)


class JWTGrantBuilder(object):
    """Creates a JWT authorization grant token.

    Requires a (private_key, service_key) key pair used to sign the JWT.
    Defaults to using a claim set that should be valid for the given
    service_key:

    - aud: token_uri from service_key
    - iss: client_id from service_key
    - sub: user_id from service_key
    - iat: Now
    - exp: Now + token lifetime
    """

    def __init__(self, session):
        self.session = session
        self.keypair = None
        self.without_claims = []
        self.arguments = {}

    def having(self, **kwargs):
        self.arguments.update(kwargs)
        return self

    def without(self, without_claims):
        self.without_claims = without_claims
        return self

    def from_keypair(self, keypair):
        self.keypair = keypair
        return self

    def create(self, **kwargs):
        if not self.keypair:
            raise Exception(
                'This builder requires a (private_key, service_key) key pair '
                'to be passed in  - use .from_keypair()')
        private_key, service_key = self.keypair

        # Determine defaults for required claims
        aud = self.arguments.get('aud', service_key['token_uri'])
        iss = self.arguments.get('iss', service_key['client_id'])
        sub = self.arguments.get('sub', service_key['user_id'],)
        iat = self.arguments.get('iat', int(time.time()))
        exp = self.arguments.get('exp', int(time.time()) + (60 * 60))

        claim_set = {
            'aud': aud,
            'iss': iss,
            'sub': sub,
            'iat': iat,
            'exp': exp,
        }

        # nbf and scope claims are not supported. So they're not included in
        # the claimset by default unless specifically requested

        nbf = self.arguments.get('nbf')
        if nbf:
            claim_set['nbf'] = nbf

        scope = self.arguments.get('scope')
        if scope:
            claim_set['scope'] = scope

        # Drop any claims that have been requested to be omitted
        if self.without_claims:
            for claim in self.without_claims:
                claim_set.pop(claim)

        grant_token = jwt.encode(claim_set, private_key, algorithm='RS256')
        return grant_token


builder_registry.register('jwt_grant', JWTGrantBuilder)


class AccessTokenBuilder(object):
    """Creates an access token tied to a service_key.

    The service_key can be passed in using .from_key(), or omitted, in which
    case one will be created using the ServiceKeyBuilder.

    A passed in key can be an actual service_key, or a ServiceKeyBuilder
    instance, which allows for chained invocations using deferred builders.
    """

    def __init__(self, session):
        self.session = session
        self.portal = getSite()
        self.plugin = self.portal.acl_users['token_auth']
        self.key_or_keybuilder = None
        self.issued_at = None
        self.arguments = {
            'user_id': TEST_USER_ID,
        }

    def having(self, **kwargs):
        self.arguments.update(kwargs)
        return self

    def from_key(self, key_or_keybuilder):
        self.key_or_keybuilder = key_or_keybuilder
        return self

    def for_user(self, user_id):
        """Shorthand to create a service_key for the given user_id, and tie
        the returned token to it.
        """
        self.arguments['user_id'] = user_id
        return self

    def issued(self, issued_at):
        # Note: This does not currently affect the usage log entry for when
        # this token gets issued. Should maybe drop this and use freezer.
        self.issued_at = issued_at
        return self

    def get_or_create_key(self):
        if self.key_or_keybuilder is None:
            # No key or key builder provided, create one with defaults
            service_key = create(
                Builder('service_key')
                .having(user_id=self.arguments.get('user_id')))
        else:
            # A deferred builder got passed in, materialize it
            if isinstance(self.key_or_keybuilder, ServiceKeyBuilder):
                service_key = create(self.key_or_keybuilder)
            else:
                # An existing service_key got passed in
                service_key = self.key_or_keybuilder
        return service_key

    def create(self, **kwargs):
        service_key = self.get_or_create_key()
        access_token = self.plugin.issue_access_token(service_key['key_id'])

        if self.issued_at:
            # Set issue date of token in storage
            storage = CredentialStorage(self.plugin)
            token_in_storage = storage.get_access_token(access_token['token'])
            token_in_storage['issued'] = self.issued_at

        return access_token

builder_registry.register('access_token', AccessTokenBuilder)
