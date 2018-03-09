from ftw.testbrowser import browsing
from ftw.testbrowser.pages import plone
from ftw.tokenauth.tests import FunctionalZServerTestCase
from plone.app.testing import TEST_USER_ID
import json
import jwt
import requests
import time


GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class TestEndToEndAuthenticationFlow(FunctionalZServerTestCase):

    @browsing
    def test_end_to_end_happy_path(self, browser):
        # Step 1 - Issue service key and save it
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()
        browser.fill({'Title': 'My new key'})
        # No IP range restriction, we test this separately
        browser.find('Issue key').click()

        self.assertEqual('Download Service Key', browser.css('h1').first.text)
        json_keyfile = browser.css('.json-keyfile').first
        keyfile_data = json.loads(json_keyfile.text)

        private_key = keyfile_data['private_key']
        token_uri = keyfile_data['token_uri']

        browser.logout().open('logout')
        self.assertFalse(plone.logged_in())

        # Step 2 - Create a JWT grant and sign it with private key
        claim_set = {
            'aud': token_uri,
            'iss': keyfile_data['client_id'],
            'sub': keyfile_data['user_id'],
            'iat': int(time.time()),
            'exp': int(time.time() + (60 * 59)),
        }
        grant_token = jwt.encode(claim_set, private_key, algorithm='RS256')

        # Step 3 - Exchange the JWT grant for an access token by making
        # a token request to the OAuth2 token endpoint
        payload = {'grant_type': GRANT_TYPE, 'assertion': grant_token}
        token_response = requests.post(token_uri, data=payload)
        token = token_response.json()['access_token']

        # Step 4 - Use the access token to make authenticated requests
        headers = {'Authorization': 'Bearer %s' % token}
        response = requests.get(self.portal.absolute_url(), headers=headers)
        self.assertIn(TEST_USER_ID, response.content)

        # Test with plone.restapi as well
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Accept': 'application/json'}

        response = requests.get(self.portal.absolute_url(), headers=headers)
        self.assertDictContainsSubset({'title': 'Plone site'}, response.json())
