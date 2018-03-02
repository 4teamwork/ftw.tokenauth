from BTrees.OOBTree import OOBTree
from ftw.builder import Builder
from ftw.builder import create
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.tests import FunctionalTestCase
from persistent.mapping import PersistentMapping
from plone.app.testing import TEST_USER_ID


class TestStorage(FunctionalTestCase):

    def test_storage_gets_initialized(self):
        storage = CredentialStorage(self.plugin)

        self.assertEqual(
            getattr(self.plugin, storage.STORAGE_NAME),
            storage._storage)

        self.assertIsInstance(storage._storage, OOBTree)

        self.assertEqual(
            storage._service_keys,
            storage._storage[storage.SERVICE_KEYS_KEY])

        self.assertEqual(
            storage._access_tokens,
            storage._storage[storage.ACCESS_TOKENS_KEY])

        self.assertIsInstance(storage._service_keys, OOBTree)
        self.assertIsInstance(storage._access_tokens, OOBTree)

    def test_initialization_is_idempotent(self):
        storage = CredentialStorage(self.plugin)
        storage._service_keys['foo'] = 'bar'
        storage._access_tokens['foo'] = 'bar'

        # Multiple initializations shouldn't remove existing data
        storage._initialize_storage()
        self.assertEqual(storage._service_keys['foo'], 'bar')
        self.assertEqual(storage._access_tokens['foo'], 'bar')

    def test_add_service_key(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))
        storage.add_service_key(service_key)

        key_from_storage = storage._service_keys[service_key['key_id']]
        self.assertIsInstance(key_from_storage, PersistentMapping)
        self.assertEqual(service_key, dict(key_from_storage))

    def test_get_service_key(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        key_from_storage = storage.get_service_key(service_key['key_id'])
        self.assertIsInstance(key_from_storage, PersistentMapping)
        self.assertEqual(service_key, dict(key_from_storage))

    def test_get_service_key_for_client_id(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        key_from_storage = storage.get_service_key_for_client_id(
            service_key['client_id'], service_key['user_id'])
        self.assertEqual(service_key, dict(key_from_storage))

    def test_list_service_keys(self):
        storage = CredentialStorage(self.plugin)

        users_keys = [
            create(Builder('service_key')),
            create(Builder('service_key')),
        ]
        create(Builder('service_key').having(user_id='other.user'))
        keys_from_storage = storage.list_service_keys(TEST_USER_ID)

        self.assertEqual(map(dict, keys_from_storage), users_keys)

    def test_revoke_service_key(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        self.assertIn(service_key['key_id'], storage._service_keys)
        storage.revoke_service_key(TEST_USER_ID, service_key['key_id'])
        self.assertNotIn(service_key['key_id'], storage._service_keys)

    def test_revoking_service_key_removes_associated_tokens(self):
        storage = CredentialStorage(self.plugin)

        service_key = create(Builder('service_key'))
        token = create(Builder('access_token')
                       .from_key(service_key))['token']

        self.assertTrue(storage.contains_access_token(token))

        storage.revoke_service_key(TEST_USER_ID, service_key['key_id'])
        self.assertFalse(storage.contains_access_token(token))

    def test_user_id_must_match_key_to_be_revoked(self):
        storage = CredentialStorage(self.plugin)
        other_key = create(Builder('service_key').having(user_id='other.user'))

        self.assertIn(other_key['key_id'], storage._service_keys)
        with self.assertRaises(AssertionError):
            storage.revoke_service_key(TEST_USER_ID, other_key['key_id'])

    def test_add_access_token(self):
        storage = CredentialStorage(self.plugin)
        access_token = create(Builder('access_token'))
        storage.add_access_token(access_token)
        token_from_storage = storage._access_tokens[access_token['token']]
        self.assertIsInstance(token_from_storage, PersistentMapping)

        # raw token string is just used as key, not stored in metadata
        access_token.pop('token')
        self.assertEqual(access_token, dict(token_from_storage))

    def test_get_access_token(self):
        storage = CredentialStorage(self.plugin)
        access_token = create(Builder('access_token'))
        storage.add_access_token(access_token)

        token = access_token['token']
        access_token_from_storage = storage.get_access_token(token)
        self.assertEqual(
            access_token_from_storage,
            storage._access_tokens[token])

    def test_contains_access_token(self):
        storage = CredentialStorage(self.plugin)
        access_token = create(Builder('access_token'))
        storage.add_access_token(access_token)

        token = access_token['token']
        self.assertTrue(storage.contains_access_token(token))
        del storage._access_tokens[token]
        self.assertFalse(storage.contains_access_token(token))
