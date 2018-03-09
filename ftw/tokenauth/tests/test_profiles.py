from ftw.tokenauth.tests import FunctionalTestCase
from plone import api
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin  # noqa
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin

PROFILE_NAME = 'ftw.tokenauth:default'


class TestDefaultProfile(FunctionalTestCase):

    def test_installed(self):
        portal_setup = api.portal.get_tool('portal_setup')
        version = portal_setup.getLastVersionForProfile(PROFILE_NAME)
        self.assertNotEqual(version, None)
        self.assertNotEqual(version, 'unknown')

    def test_pas_plugin_installed_in_plone_acl_users(self):
        acl_users = self.portal.acl_users
        self.assertIn('token_auth', acl_users.objectIds())
        token_auth_plugin = acl_users['token_auth']

        activated_interfaces = [
            iface for iface, plugin_ids
            in acl_users.plugins._plugins.items()
            if token_auth_plugin.id in plugin_ids
        ]

        self.assertEqual(
            set([IExtractionPlugin, IAuthenticationPlugin]),
            set(activated_interfaces))

    def test_pas_plugin_not_installed_in_zope_acl_users(self):
        zope_acl_users = self.portal.aq_parent.acl_users
        self.assertNotIn('token_auth', zope_acl_users.objectIds())
