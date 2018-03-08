from BTrees.OOBTree import OOBTree
from datetime import datetime
from datetime import timedelta
from operator import itemgetter
from persistent.list import PersistentList
from persistent.mapping import PersistentMapping
from plone import api
from Products.CMFPlone.utils import base_hasattr
from zExceptions import Unauthorized
from zope.globalrequest import getRequest


class CredentialStorage(object):
    """Storage abstraction for service keys, access tokens, and usage logs.

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
    USAGE_LOGS_KEY = 'usage_logs'

    def __init__(self, plugin):
        self.plugin = plugin

        if not base_hasattr(self.plugin, self.STORAGE_NAME):
            # Initialize storage. Will be triggered upon first plugin
            # instanciation (i.e, install time).
            self._initialize_storage()

        self._storage = getattr(self.plugin, self.STORAGE_NAME)

        self._service_keys = self._storage[self.SERVICE_KEYS_KEY]
        self._access_tokens = self._storage[self.ACCESS_TOKENS_KEY]
        self._usage_logs = self._storage[self.USAGE_LOGS_KEY]

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

            if self.USAGE_LOGS_KEY not in _storage:
                _storage[self.USAGE_LOGS_KEY] = OOBTree()

    def _assert_current_user_owns_key(self, key_id):
        """Verify that the currently logged in user owns the given key.
        """
        current_user = api.user.get_current()
        service_key = self.get_service_key(key_id, unrestricted=True)

        if not service_key or service_key['user_id'] != current_user.id:
            raise Unauthorized()

    def add_service_key(self, service_key):
        """Store a service key (dict with public key and metadata).
        """
        key_id = service_key['key_id']
        self._service_keys[key_id] = PersistentMapping(service_key)
        return key_id

    def get_service_key(self, key_id, unrestricted=False):
        """Return the service key identified by key_id.

        Unless invoked with unrestricted=True, this method only allows to
        fetch service keys for the current user.
        """
        if not unrestricted:
            self._assert_current_user_owns_key(key_id)

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

    def revoke_service_key(self, user_id, key_id, unrestricted=False):
        """Revoke the service_key identified by key_id.

        Also removes any access tokens tied to this key.

        Unless invoked with unrestricted=True, this method only allows
        revocation of keys belonging to the currently logged in user.
        """
        if not unrestricted:
            self._assert_current_user_owns_key(key_id)

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
        assert self.get_service_key(access_token['key_id'], unrestricted=True)

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

    def log_access_token_creation(self, access_token):
        """Write a usage_log entry for the issued access_token.

        Also triggers rotation of usage logs older than retention period.
        """
        key_id = access_token['key_id']
        if key_id not in self._usage_logs:
            # TODO: Maybe use a BTree set here?
            self._usage_logs[key_id] = PersistentList()

        ip_address = getRequest().getClientAddr()
        log_entry = PersistentMapping({
            'issued': access_token['issued'],
            'ip_address': ip_address})
        self._usage_logs[key_id].append(log_entry)

        self.rotate_usage_logs()

    def clean_up_expired_tokens(self):
        """Remove expired tokens from storage.
        """
        for token, access_token in self._access_tokens.items():
            if self.plugin.is_expired(access_token):
                del self._access_tokens[token]

    def get_last_used(self, key_id, unrestricted=False):
        """Determine when the key was last used to issue an access token.

        Unless invoked with unrestricted=True, this method only allows to
        fetch the last used date for keys belonging to the current user.
        """
        entries = self.get_usage_logs(key_id, unrestricted=unrestricted)
        if entries:
            return entries[-1]['issued']
        return '(Never)'

    def get_usage_logs(self, key_id, unrestricted=False):
        """Get usage logs for the key identified by key_id.

        Unless invoked with unrestricted=True, this method only allows to
        retrieve usage logs for keys belonging to the current user.
        """
        if not unrestricted:
            self._assert_current_user_owns_key(key_id)

        entries = sorted(self._usage_logs.get(key_id, []),
                         key=itemgetter('issued'))
        return entries

    def rotate_usage_logs(self):
        """Clean out expired usage log entries.

        Usage log entries older than retention period will be removed, except
        the most recent entry, which will always be kept.
        """
        for key_id, entries in self._usage_logs.items():
            last_used = self.get_last_used(key_id, unrestricted=True)
            for entry in entries:
                issued = entry['issued']
                max_age = timedelta(days=self.plugin.usage_log_retention_days)
                # If entry is expired and not the most recent one, remove it
                if datetime.now() - issued > max_age and issued != last_used:
                    entries.remove(entry)
