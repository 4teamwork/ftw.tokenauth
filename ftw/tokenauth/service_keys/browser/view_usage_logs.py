from ftw.tokenauth.pas.storage import CredentialStorage
from plone import api
from Products.Five.browser import BrowserView


class ViewUsageLogs(BrowserView):

    def __call__(self):
        acl_users = api.portal.get().acl_users
        plugin = acl_users['token_auth']
        self.storage = CredentialStorage(plugin)

        self.request.set('disable_border', True)
        self.key_id = self.request.form['key_id']
        key_title = self.get_key_title()
        return self.index(key_title=key_title)

    def get_key_title(self):
        service_key = self.storage.get_service_key(self.key_id)
        return service_key['title']

    def get_usage_logs(self):
        entries = self.storage.get_usage_logs(self.key_id)
        return entries
