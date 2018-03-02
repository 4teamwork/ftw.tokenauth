from ftw.tokenauth.pas.storage import CredentialStorage
from plone import api
from Products.Five.browser import BrowserView


class ManageServiceKeysView(BrowserView):

    def __call__(self):
        acl_users = api.portal.get().acl_users
        self.plugin = acl_users['token_auth']

        self.request.set('disable_border', True)
        return self.index()

    @property
    def main_url(self):
        return self.context.absolute_url() + '/@@manage-service-keys'

    def get_key_infos(self):
        user_id = api.user.get_current().id
        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(user_id)

        # TODO: Should we maybe include the grant life time as well?
        # (client needs that to set 'exp' claim)

        key_infos = [
            {'client_id': key['client_id'],
             'key_id': key['key_id'],
             'title': key['title'],
             'issued': key['issued']}
            for key in users_keys]

        return key_infos
