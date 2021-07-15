from ftw.tokenauth import _
from plone import api
from plone.restapi.deserializer import json_body
from plone.restapi.services import Service
from zope.interface import alsoProvides

import datetime
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
        result = {
            "@id": service_key_id,
            "service_key": self.format_service_key(service_key),
        }
        self.request.response.setHeader(
            "Location",
            f"{self.context.absolute_url()}/@service-keys/{service_key['key_id']}",
        )
        self.request.response.setStatus(201)
        return result

    def format_service_key(self, service_key):
        new_service_key = {}
        for key, value in service_key.items():
            if isinstance(value, datetime.datetime):
                new_service_key[key] = value.isoformat()
            else:
                new_service_key[key] = value

        return new_service_key
