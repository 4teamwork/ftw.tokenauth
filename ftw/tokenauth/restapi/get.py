from ftw.tokenauth import _
from ftw.tokenauth.pas.storage import CredentialStorage
from plone import api
from plone.restapi.deserializer import json_body
from plone.restapi.services import Service

import datetime


class GetTokens(Service):
    def get_plugin(self):
        acl_users = api.portal.get().acl_users
        return acl_users["token_auth"]

    def reply(self):
        if api.user.is_anonymous():
            self.request.response.setStatus(401)
            return {}

        return self.get_key_infos()

    def get_key_infos(self):
        user_id = api.user.get_current().id
        storage = CredentialStorage(self.get_plugin())
        users_keys = storage.list_service_keys(user_id)

        # TODO: Should we maybe include the grant life time as well?
        # (client needs that to set 'exp' claim)

        key_infos = [
            {
                "client_id": key["client_id"],
                "key_id": key["key_id"],
                "title": key["title"],
                "ip_range": key["ip_range"],
                "issued": key["issued"].isoformat(),
                "last_used": self.get_last_used(key["key_id"]),
            }
            for key in users_keys
        ]

        result = {
            "@id": f"{self.context.absolute_url()}/@service-keys",
            "items": key_infos,
        }

        return result

    def get_last_used(self, key_id):
        storage = CredentialStorage(self.get_plugin())
        last_used = storage.get_last_used(key_id)
        if last_used:
            if isinstance(last_used, datetime.datetime):
                return last_used.isoformat()

            return last_used

        return None
