from ftw.builder.testing import BUILDER_LAYER
from ftw.testbrowser import REQUESTS_BROWSER_FIXTURE
from plone.app.testing import applyProfile
from plone.app.testing import FunctionalTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.testing import Layer
from plone.testing import z2
from zope.configuration import xmlconfig


DEFAULT_TESTING_TOKEN_URI = 'http://nohost/plone/@@oauth2-token'


class FtwTokenAuthLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE, BUILDER_LAYER)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import ftw.tokenauth
        xmlconfig.file(
            'configure.zcml',
            ftw.tokenauth,
            context=configurationContext
        )
        z2.installProduct(app, 'ftw.tokenauth')

        import plone.restapi
        xmlconfig.file(
            'configure.zcml',
            plone.restapi,
            context=configurationContext
        )
        z2.installProduct(app, 'plone.restapi')

    def setUpPloneSite(self, portal):
        applyProfile(portal, 'ftw.tokenauth:default')
        uf = portal.acl_users
        self['plugin'] = uf['token_auth']

        applyProfile(portal, 'plone.restapi:default')


FTW_TOKENAUTH_FIXTURE = FtwTokenAuthLayer()
FTW_TOKENAUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_TOKENAUTH_FIXTURE,),
    name="FtwtokenauthLayer:Functional"
)

FTW_TOKENAUTH_FUNCTIONAL_ZSERVER_TESTING = FunctionalTesting(
    bases=(FTW_TOKENAUTH_FIXTURE,
           z2.ZSERVER_FIXTURE,
           REQUESTS_BROWSER_FIXTURE),
    name="FtwtokenauthLayer:FunctionalZServer"
)


class UnitTesting(Layer):
    """Layer for using ftw.builder in unit tests.
    """

    defaultBases = (BUILDER_LAYER, )

FTW_TOKENAUTH_UNIT_TESTING = UnitTesting()
