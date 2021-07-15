from ftw.tokenauth.tests import FunctionalZServerTestCase
from plone import api
from plone.restapi.testing import RelativeSession
import transaction


TEST_USER_ID = "test"
TEST_USER_PASSWORD = "secret"


class TestRestApi(FunctionalZServerTestCase):
    def setUp(self):
        super(TestRestApi, self).setUp()

        uf = api.portal.get_tool("acl_users")
        uf.source_users.addUser(TEST_USER_ID, TEST_USER_ID, TEST_USER_PASSWORD)
        uf.portal_role_manager.doAssignRoleToPrincipal(TEST_USER_ID, "Member")

        self.portal_url = self.portal.absolute_url()
        self.api_session = RelativeSession(self.portal_url)
        self.api_session.headers.update({"Accept": "application/json"})
        self.api_session.auth = (TEST_USER_ID, TEST_USER_PASSWORD)
        self.anon_api_session = RelativeSession(self.portal_url)
        self.anon_api_session.headers.update({"Accept": "application/json"})
        transaction.commit()

    def test_get_service_keys_anonymous_user(self):
        response = self.anon_api_session.get("/@service-keys")
        self.assertEqual(401, response.status_code)

    def test_get_service_keys(self):
        response = self.api_session.get(
            "/@service-keys",
        )

        self.assertEqual(200, response.status_code)

        self.assertTrue("@id" in response.json())
        self.assertEqual([], response.json()["items"])

    def test_create_service_key_anonymous_user(self):
        response = self.anon_api_session.post("/@service-keys")
        self.assertEqual(401, response.status_code)

    def test_create_service_key_without_title(self):
        response = self.api_session.post("/@service-keys", json={})

        self.assertEqual(400, response.status_code)

    def test_create_service_key(self):
        service_key_title = "title of this service-key"
        response = self.api_session.post(
            "/@service-keys", json={"title": service_key_title}
        )

        self.assertEqual(201, response.status_code)
        response_json = response.json()
        self.assertTrue("service_key" in response_json)
        self.assertEqual(
            response_json["service_key"]["title"], "title of this service-key"
        )

    def test_created_service_key_is_available(self):
        service_key_title = "title of this service-key"
        response = self.api_session.post(
            "/@service-keys", json={"title": service_key_title}
        )

        self.assertEqual(201, response.status_code)
        response_json = response.json()
        service_key_id = response_json["service_key"]["key_id"]
        response = self.api_session.get(
            "/@service-keys",
        )

        self.assertEqual(200, response.status_code)
        self.assertTrue("@id" in response.json())
        self.assertEqual(1, len(response.json()["items"]))

        self.assertEqual(service_key_id, response.json()["items"][0]["key_id"])

    def test_delete_service_key(self):
        service_key_title = "title of this service-key"
        response = self.api_session.post(
            "/@service-keys", json={"title": service_key_title}
        )

        self.assertEqual(201, response.status_code)
        response_json = response.json()
        service_key_id = response_json["service_key"]["key_id"]

        response = self.api_session.delete(f"/@service-keys/{service_key_id}")

        self.assertEqual(204, response.status_code)

    def test_delete_inexistent_service_key(self):
        response = self.api_session.delete(f"/@service-keys/inexistent-service-key-id")
        self.assertEqual(400, response.status_code)

    def test_delete_service_key_is_really_deleted(self):
        service_key_title = "title of this service-key"
        response = self.api_session.post(
            "/@service-keys", json={"title": service_key_title}
        )

        self.assertEqual(201, response.status_code)
        response_json = response.json()
        service_key_id = response_json["service_key"]["key_id"]

        response = self.api_session.delete(f"/@service-keys/{service_key_id}")

        self.assertEqual(204, response.status_code)

        response = self.api_session.get(
            "/@service-keys",
        )

        self.assertEqual(200, response.status_code)
        self.assertTrue("@id" in response.json())
        self.assertEqual([], response.json()["items"])
