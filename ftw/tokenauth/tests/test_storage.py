from BTrees.OOBTree import OOBTree
from datetime import datetime
from ftw.builder import Builder
from ftw.builder import create
from ftw.testing import freeze
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.tests import FunctionalTestCase
from persistent.mapping import PersistentMapping
from plone.app.testing import TEST_USER_ID
from zExceptions import Unauthorized


FROZEN_NOW = datetime.now()


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

        self.assertEqual(
            storage._usage_logs,
            storage._storage[storage.USAGE_LOGS_KEY])

        self.assertIsInstance(storage._service_keys, OOBTree)
        self.assertIsInstance(storage._access_tokens, OOBTree)
        self.assertIsInstance(storage._usage_logs, OOBTree)

    def test_initialization_is_idempotent(self):
        storage = CredentialStorage(self.plugin)
        storage._service_keys['foo'] = 'bar'
        storage._access_tokens['foo'] = 'bar'
        storage._usage_logs['foo'] = 'bar'

        # Multiple initializations shouldn't remove existing data
        storage._initialize_storage()
        self.assertEqual(storage._service_keys['foo'], 'bar')
        self.assertEqual(storage._access_tokens['foo'], 'bar')
        self.assertEqual(storage._usage_logs['foo'], 'bar')

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

    def test_cant_revoke_other_users_keys(self):
        storage = CredentialStorage(self.plugin)
        other_key = create(Builder('service_key').having(user_id='other.user'))

        self.assertIn(other_key['key_id'], storage._service_keys)
        with self.assertRaises(Unauthorized):
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

    def test_log_access_token_creation(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        self.request._client_addr = '192.168.1.1'
        with freeze(datetime(2018, 1, 1, 15, 30)):
            create(Builder('access_token').from_key(service_key))

        self.assertEqual(
            {service_key['key_id']: [
                {'issued': datetime(2018, 1, 1, 15, 30),
                 'ip_address': '192.168.1.1'}]},
            dict(storage._usage_logs))

    def test_get_usage_logs(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        self.request._client_addr = '192.168.1.1'
        with freeze(datetime(2018, 1, 10, 15, 30)) as clock:
            create(Builder('access_token').from_key(service_key))
            clock.backward(hours=1)
            create(Builder('access_token').from_key(service_key))

        # Should be ordered by 'issued'
        self.assertEqual(
            [
                {'issued': datetime(2018, 1, 10, 14, 30),
                 'ip_address': '192.168.1.1'},
                {'issued': datetime(2018, 1, 10, 15, 30),
                 'ip_address': '192.168.1.1'},
            ],
            storage.get_usage_logs(service_key['key_id']))

    def test_cant_fetch_logs_for_other_users_key(self):
        storage = CredentialStorage(self.plugin)
        other_key = create(Builder('service_key').having(user_id='other.user'))
        create(Builder('access_token').from_key(other_key))

        with self.assertRaises(Unauthorized):
            storage.get_usage_logs(other_key['key_id'])

    def test_get_last_used(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        self.request._client_addr = '192.168.1.1'
        with freeze(datetime(2018, 1, 10, 15, 30)):
            create(Builder('access_token').from_key(service_key))

        self.assertEqual(
            datetime(2018, 1, 10, 15, 30),
            storage.get_last_used(service_key['key_id']))

    def test_rotates_usage_logs(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        with freeze(datetime(2018, 1, 10, 15, 30)) as clock:
            # First one should be rotated (older than 7 days)
            create(Builder('access_token').from_key(service_key))
            clock.forward(days=10)
            create(Builder('access_token').from_key(service_key))
            clock.forward(hours=2)
            create(Builder('access_token').from_key(service_key))

        self.assertEqual(
            {service_key['key_id']: [
                {'issued': datetime(2018, 1, 20, 15, 30),
                 'ip_address': ''},
                {'issued': datetime(2018, 1, 20, 17, 30),
                 'ip_address': ''},
            ]},
            dict(storage._usage_logs))

    def test_rotate_usage_logs_never_removes_most_recent_entry(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        with freeze(datetime(2018, 1, 10, 15, 30)) as clock:
            # Expired enty, but shouldn't be rotated because it's the most
            # recent one
            create(Builder('access_token').from_key(service_key))

            clock.forward(days=60)
            storage.rotate_usage_logs()

        self.assertEqual(
            {service_key['key_id']: [
                {'issued': datetime(2018, 1, 10, 15, 30),
                 'ip_address': ''},
            ]},
            dict(storage._usage_logs))

    def test_respects_custom_usage_log_retention_period(self):
        storage = CredentialStorage(self.plugin)
        service_key = create(Builder('service_key'))

        self.plugin.usage_log_retention_days = 30

        with freeze(datetime(2018, 1, 10, 15, 30)) as clock:
            # First one would be rotated with default settings (7 days),
            # but shouldn't with a higher setting of 30 days
            create(Builder('access_token').from_key(service_key))
            clock.forward(days=10)
            create(Builder('access_token').from_key(service_key))

        self.assertIn(
            {'issued': datetime(2018, 1, 10, 15, 30),
             'ip_address': ''},
            dict(storage._usage_logs)[service_key['key_id']])
