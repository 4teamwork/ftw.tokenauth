from ftw.tokenauth import _
from ftw.tokenauth.service_keys.browser.issue import create_json_keyfile
from plone import api
from plone.restapi.deserializer import json_body
from plone.restapi.services import Service
from zope.interface import alsoProvides

import json
import plone.protect.interfaces


class CreateToken(Service):
    def get_plugin(self):
        acl_users = api.portal.get().acl_users
        return acl_users["token_auth"]

    def reply(self):
        if api.user.is_anonymous():
            self.request.response.setStatus(401)
            return {}

        if "IDisableCSRFProtection" in dir(plone.protect.interfaces):
            alsoProvides(self.request, plone.protect.interfaces.IDisableCSRFProtection)

        data = json_body(self.request)

        if "title" not in data:
            self.request.response.setStatus(400)
            message = _("You need to provide at least a title for the service key")
            return {"error": {"type": "error", "message": message}}

        user_id = api.user.get_current().id

        private_key, service_key = self.get_plugin().issue_keypair(
            user_id, data.get("title"), data.get("ip_range", "")
        )

        self._key_issued = True
        self._generated_private_key = private_key
        self._generated_service_key = service_key

        service_key_id = (
            f"{self.context.absolute_url()}/@service-keys/{service_key['key_id']}"
        )

        service_key_json = json.loads(create_json_keyfile(private_key, service_key))
        service_key_json.update(
            {"title": data.get("title"), "ip_range": data.get("ip_range")}
        )

        result = {
            "@id": service_key_id,
            "service_key": service_key_json,
        }
        self.request.response.setHeader(
            "Location",
            f"{self.context.absolute_url()}/@service-keys/{service_key['key_id']}",
        )
        self.request.response.setStatus(201)
        return result
