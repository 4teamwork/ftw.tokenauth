from ftw.tokenauth.pas.storage import CredentialStorage
from plone import api
from Products.Five.browser import BrowserView
from zope.globalrequest import getRequest


class ManageServiceKeysView(BrowserView):

    def __call__(self):
        acl_users = api.portal.get().acl_users
        self.plugin = acl_users['token_auth']

        action = self.request.form.get('action')
        if action == 'Revoke selected keys':
            return self.revoke_selected_keys()

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
             'ip_range': key['ip_range'],
             'issued': key['issued']}
            for key in users_keys]

        return key_infos

    def revoke_selected_keys(self):
        user_id = api.user.get_current().id
        selected_keys = self.request.form.get('selected_keys', [])

        storage = CredentialStorage(self.plugin)
        for key_id in selected_keys:
            storage.revoke_service_key(user_id, key_id)

        api.portal.show_message('Keys revoked.', getRequest())
        return self.request.RESPONSE.redirect(self.main_url)
