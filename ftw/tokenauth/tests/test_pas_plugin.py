from datetime import datetime
from datetime import timedelta
from ftw.builder import Builder
from ftw.builder import create
from ftw.testing import freeze
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.tests import FunctionalTestCase
from plone.app.testing import TEST_USER_ID
import json


class TestTokenAuthPlugin(FunctionalTestCase):

    def test_extract_credentials_without_authorization_header(self):
        self.request._auth = ''
        self.assertEqual(None, self.plugin.extractCredentials(self.request))

    def test_extract_credentials_with_other_authorization_header(self):
        self.request._auth = 'Basic YWRtaW46YWRtaW4='
        self.assertEqual(None, self.plugin.extractCredentials(self.request))

    def test_extract_credentials_with_bearer_authorization_header(self):
        self.request._auth = 'Bearer <some-access-token>'

        self.assertEqual(
            {'access_token': '<some-access-token>'},
            self.plugin.extractCredentials(self.request))

    def test_authenticate_credentials_from_unknown_extractor(self):
        creds = {
            'extractor': 'credentials_basic_auth',
        }
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))

    def test_authenticate_credentials_with_invalid_token(self):
        creds = {
            'extractor': 'token_auth',
            'access_token': 'invalid',
        }
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))

    def test_authenticate_credentials_with_valid_token(self):
        creds = {
            'extractor': 'token_auth',
            'access_token': create(Builder('access_token'))['token'],
        }
        self.assertEqual(
            (TEST_USER_ID, TEST_USER_ID),
            self.plugin.authenticateCredentials(creds))

    def test_authenticate_credentials_rejects_expired_token(self):
        # Create an expired token
        access_token = create(Builder('access_token')
                              .issued(datetime.now() - timedelta(hours=2)))

        creds = {
            'extractor': 'token_auth',
            'access_token': access_token['token'],
        }
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))
        self.assertEqual(401, self.request.response.getStatus())
        self.assertEqual(
            json.dumps({'error_description': 'Access token expired',
                        'error': 'invalid_token'}),
            self.request.response.getBody())

    def test_authenticate_credentials_honours_customized_token_lifetime(self):
        # Create a token that would be expired within the default access token
        # lifetime (3600s), but is valid using a customized one
        self.plugin.access_token_lifetime = 9600
        access_token = create(Builder('access_token')
                              .issued(datetime.now() - timedelta(hours=2)))

        creds = {
            'extractor': 'token_auth',
            'access_token': access_token['token'],
        }

        self.assertEqual(
            (TEST_USER_ID, TEST_USER_ID),
            self.plugin.authenticateCredentials(creds))

    def test_authenticate_credentials_rejects_unknown_user(self):
        access_token = create(Builder('access_token').for_user('unknown.user'))
        creds = {
            'extractor': 'token_auth',
            'access_token': access_token['token'],
        }
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))

    def test_cleans_up_expired_tokens(self):
        storage = CredentialStorage(self.plugin)

        with freeze(datetime(2018, 1, 1, 15, 30)) as clock:
            token_1 = create(Builder('access_token'))['token']
            self.assertTrue(storage.contains_access_token(token_1))

            # Two hours later, the first token should have expired and
            # get cleaned up when issuing another token
            clock.forward(hours=2)
            token_2 = create(Builder('access_token'))['token']
            self.assertFalse(storage.contains_access_token(token_1))
            self.assertTrue(storage.contains_access_token(token_2))

            # ...but non-expired tokens stay in storage
            clock.forward(minutes=5)
            token_3 = create(Builder('access_token'))['token']
            self.assertTrue(storage.contains_access_token(token_2))
            self.assertTrue(storage.contains_access_token(token_3))
