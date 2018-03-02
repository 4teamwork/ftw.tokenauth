from ftw.builder import Builder
from ftw.builder import create
from ftw.testbrowser import browsing
from ftw.tokenauth.oauth2.browser.oauth2_token import JWT_BEARER_GRANT_TYPE
from ftw.tokenauth.tests import FunctionalTestCase
from plone.app.testing import TEST_USER_ID
import jwt
import transaction


class TestOAuth2TokenEndpoint(FunctionalTestCase):

    def setUp(self):
        super(TestOAuth2TokenEndpoint, self).setUp()
        self.keypair = self.plugin.issue_keypair(
            TEST_USER_ID,
            'My Service Key')

        self.valid_assertion = create(
            Builder('jwt_grant').from_keypair(self.keypair))

        transaction.commit()

    @browsing
    def test_only_accepts_post(self, browser):
        with browser.expect_http_error(code=405):
            browser.login().open(view='@@oauth2-token')

        self.assertEqual(
            {'error': 'invalid_request',
             'error_description': 'POST only'},
            browser.json)

    @browsing
    def test_sets_cache_headers(self, browser):
        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': self.valid_assertion}

        browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertDictContainsSubset(
            {'Pragma': 'no-cache',
             'Cache-Control': 'no-store'},
            browser.headers)

    @browsing
    def test_sets_content_type_header(self, browser):
        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': self.valid_assertion}

        browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertDictContainsSubset(
            {'Content-Type': 'application/json'},
            browser.headers)

    @browsing
    def test_rejects_missing_grant_types(self, browser):
        data = {'assertion': self.valid_assertion}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_request',
             'error_description': "Missing 'grant_type'"},
            browser.json)

    @browsing
    def test_rejects_unknown_grant_types(self, browser):
        data = {'grant_type': 'unknown',
                'assertion': self.valid_assertion}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_request',
             'error_description': "Only grant type '%s' is "
                                  "supported" % JWT_BEARER_GRANT_TYPE},
            browser.json)

    @browsing
    def test_rejects_missing_assertion(self, browser):
        data = {'grant_type': JWT_BEARER_GRANT_TYPE}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_request',
             'error_description': "Missing 'assertion'"},
            browser.json)

    @browsing
    def test_rejects_unsupported_signature_algorithm(self, browser):
        not_stored_keypair = create(Builder('keypair'))
        private_key = not_stored_keypair[0]

        # Create (empty) JWT with unsupported signature algorithm
        assertion = jwt.encode({}, private_key, algorithm='HS256')

        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': assertion}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_request',
             'error_description': 'Only RS256 signature algorithm '
                                  'is supported'},
            browser.json)

    @browsing
    def test_rejects_unknown_service_key(self, browser):
        not_stored_keypair = create(Builder('keypair'))
        assertion = create(Builder('jwt_grant')
                           .from_keypair(not_stored_keypair))

        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': assertion}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_grant',
             'error_description': 'No associated key found'},
            browser.json)

    @browsing
    def test_rejects_invalid_jwt_assertion(self, browser):
        # In-depth tests for JWT grant validation are tested in
        # ftw.tokenauth.tests.test_jwt_grant_validation.py
        invalid_assertion = create(Builder('jwt_grant')
                                   .having(aud='http://bogus.example.org')
                                   .from_keypair(self.keypair))

        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': invalid_assertion}

        with browser.expect_http_error(code=400):
            browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            {'error': 'invalid_grant',
             'error_description': 'Invalid audience'},
            browser.json)

    @browsing
    def test_issues_access_token_for_valid_grant(self, browser):
        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': self.valid_assertion}

        browser.open(view='@@oauth2-token', method='POST', data=data)

        self.assertEqual(
            ['access_token', 'token_type', 'expires_in'],
            browser.json.keys())
        self.assertDictContainsSubset(
            {'token_type': 'Bearer',
             'expires_in': 3600},
            browser.json)

        # Make sure the token we got is valid and can be used to authenticate
        token = browser.json['access_token']
        creds = {'access_token': token, 'extractor': 'token_auth'}
        self.assertEqual(
            (TEST_USER_ID, TEST_USER_ID),
            self.plugin.authenticateCredentials(creds))

    @browsing
    def test_respects_custom_access_token_lifetime(self, browser):
        self.plugin.access_token_lifetime = 7200
        transaction.commit()

        data = {'grant_type': JWT_BEARER_GRANT_TYPE,
                'assertion': self.valid_assertion}

        browser.open(view='@@oauth2-token', method='POST', data=data)
        self.assertDictContainsSubset({'expires_in': 7200}, browser.json)
