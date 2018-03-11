from AccessControl.Permissions import add_user_folders
from ftw.tokenauth.pas import plugin
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin  # noqa
from zope.i18nmessageid import MessageFactory


_ = MessageFactory('ftw.tokenauth')


def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    registerMultiPlugin(plugin.TokenAuthenticationPlugin.meta_type)
    context.registerClass(
        plugin.TokenAuthenticationPlugin,
        permission=add_user_folders,
        constructors=(plugin.manage_addTokenAuthenticationPlugin,
                      plugin.addTokenAuthenticationPlugin),
        visibility=None,
    )
