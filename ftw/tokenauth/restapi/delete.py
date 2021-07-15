from ftw.tokenauth import _
from ftw.tokenauth.pas.storage import CredentialStorage
from plone import api
from plone.restapi.deserializer import json_body
from plone.restapi.services import Service
from zope.interface import alsoProvides
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse

import plone.protect.interfaces


@implementer(IPublishTraverse)
class DeleteToken(Service):
    def __init__(self, context, request):
        super().__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        # Consume any path segments after /@service-keys as parameters
        self.params.append(name)
        return self

    @property
    def _get_key_id(self):
        if len(self.params) != 1:
            return None
        return self.params[0].strip()

    def get_plugin(self):
        acl_users = api.portal.get().acl_users
        return acl_users["token_auth"]

    def reply(self):

        if api.user.is_anonymous():
            self.request.response.setStatus(401)
            return {}

        if "IDisableCSRFProtection" in dir(plone.protect.interfaces):
            alsoProvides(self.request, plone.protect.interfaces.IDisableCSRFProtection)

        user_id = api.user.get_current().id
        key_id = self._get_key_id

        storage = CredentialStorage(self.get_plugin())

        if key_id:
            try:
                storage.revoke_service_key(user_id, key_id)

                self.request.response.setStatus(204)
                return {}
            except KeyError:
                message = _("There is no key with such id")
                self.request.response.setStatus(400)
                return {"error": {"type": "error", "message": message}}
        else:
            message = _("There is no key with such id")
            self.request.response.setStatus(400)
            return {"error": {"type": "error", "message": message}}
