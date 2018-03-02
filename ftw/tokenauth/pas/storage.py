from BTrees.OOBTree import OOBTree
from operator import itemgetter
from persistent.mapping import PersistentMapping
from plone import api
from Products.CMFPlone.utils import base_hasattr


class CredentialStorage(object):
    """Storage abstraction for service keys and access tokens.

    The storage's internal data structured are kept as attributes on the
    PAS plugin.

    In terms of permformance, they are organized in a way that is optimized
    for answering the question 'is this token in the storage?' quickly, as
    well as fetching said token's metadata. This is because this will have
    to be checked for every request authenticating with a token.

    Every other operation is secondary to that in terms of performance, and
    more cumbersome lookups are acceptable.
    """

    STORAGE_NAME = '_credential_storage'

    SERVICE_KEYS_KEY = 'service_keys'
    ACCESS_TOKENS_KEY = 'access_tokens'

    def __init__(self, plugin):
        self.plugin = plugin

        if not base_hasattr(self.plugin, self.STORAGE_NAME):
            # Initialize storage. Will be triggered upon first plugin
            # instanciation (i.e, install time).
            self._initialize_storage()

        self._storage = getattr(self.plugin, self.STORAGE_NAME)

        self._service_keys = self._storage[self.SERVICE_KEYS_KEY]
        self._access_tokens = self._storage[self.ACCESS_TOKENS_KEY]

    def _initialize_storage(self):
        """Initialize internal data structures of the storage.
        """
        if not base_hasattr(self.plugin, self.STORAGE_NAME):
            setattr(self.plugin, self.STORAGE_NAME, OOBTree())
            _storage = self.plugin._credential_storage

            if self.SERVICE_KEYS_KEY not in _storage:
                _storage[self.SERVICE_KEYS_KEY] = OOBTree()

            if self.ACCESS_TOKENS_KEY not in _storage:
                _storage[self.ACCESS_TOKENS_KEY] = OOBTree()

    def add_service_key(self, service_key):
        """Store a service key (dict with public key and metadata).
        """
        key_id = service_key['key_id']
        self._service_keys[key_id] = PersistentMapping(service_key)
        return key_id

    def get_service_key(self, key_id):
        """Return the service key identified by key_id.
        """
        return self._service_keys[key_id]

    def get_service_key_for_client_id(self, client_id, user_id):
        """Return the service_key tied to client_id and user_id.
        """
        keys = self.list_service_keys(user_id)
        keys_for_client_id = [
            k for k in keys
            if k['client_id'] == client_id]

        if not keys_for_client_id:
            return None

        assert len(keys_for_client_id) == 1
        return keys_for_client_id[0]

    def list_service_keys(self, user_id):
        """Return all service_keys associated with user_id.
        """
        users_keys = [
            k for k in self._service_keys.values()
            if k['user_id'] == user_id]

        return sorted(users_keys, key=itemgetter('issued'))

    def revoke_service_key(self, user_id, key_id):
        """Revoke the service_key identified by key_id.

        Also removes any access tokens tied to this key.
        """
        key = self._service_keys[key_id]

        assert key_id in self._service_keys
        assert key['user_id'] == user_id
        assert api.user.get_current().id == user_id

        self._service_keys.pop(key_id)

        # Remove any tokens tied to this key
        for token, access_token in self._access_tokens.items():
            if access_token['key_id'] == key_id:
                del self._access_tokens[token]

    def add_access_token(self, access_token):
        """Store the given access_token (dict with raw token and metadata).
        """
        # Verify that service key exists
        assert self.get_service_key(access_token['key_id'])

        # The raw token itself isn't stored in metadata, just used as a key
        token = access_token['token']
        self._access_tokens[token] = PersistentMapping({
            'key_id': access_token['key_id'],
            'issued': access_token['issued'],
            'expires_in': access_token['expires_in'],
        })

    def get_access_token(self, token):
        """Return the access_token metadata for `token`.
        """
        return self._access_tokens.get(token)

    def contains_access_token(self, token):
        """Check whether the raw token `token` is in storage.
        """
        return token in self._access_tokens

    def clean_up_expired_tokens(self):
        """Remove expired tokens from storage.
        """
        for token, access_token in self._access_tokens.items():
            if self.plugin.is_expired(access_token):
                del self._access_tokens[token]
