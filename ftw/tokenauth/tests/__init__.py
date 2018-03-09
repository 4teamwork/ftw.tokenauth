from ftw.tokenauth.permissions import ManageOwnServiceKeys
from ftw.tokenauth.testing import FTW_TOKENAUTH_FUNCTIONAL_TESTING
from ftw.tokenauth.testing import FTW_TOKENAUTH_FUNCTIONAL_ZSERVER_TESTING
from plone import api
from unittest2 import TestCase
import transaction


class FunctionalTestCase(TestCase):

    layer = FTW_TOKENAUTH_FUNCTIONAL_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']
        uf = api.portal.get_tool('acl_users')
        self.plugin = uf['token_auth']
        self.portal.manage_permission(ManageOwnServiceKeys, roles=['Member'])
        transaction.commit()


class FunctionalZServerTestCase(TestCase):

    layer = FTW_TOKENAUTH_FUNCTIONAL_ZSERVER_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']
        uf = api.portal.get_tool('acl_users')
        self.plugin = uf['token_auth']
        self.portal.manage_permission(ManageOwnServiceKeys, roles=['Member'])
        transaction.commit()
