from ftw.tokenauth.pas.plugin import TokenAuthenticationPlugin
from plone import api


def default_profile_installed(site):
    install_token_auth_plugin(site)


def default_profile_uninstalled(site):
    remove_token_auth_plugin(site)


def install_token_auth_plugin(site):
    """Install the token auth plugin into Plone's acl_users.
    """
    uf = api.portal.get_tool('acl_users')
    if 'token_auth' not in uf:
        plugin = TokenAuthenticationPlugin('token_auth')
        uf._setObject(plugin.getId(), plugin)
        plugin = uf['token_auth']
        plugin.manage_activateInterfaces([
            'IAuthenticationPlugin',
            'IExtractionPlugin',
        ])


def remove_token_auth_plugin(site):
    """Remove the token auth plugin from Plone's acl_users.
    """
    uf = api.portal.get_tool('acl_users')
    if 'token_auth' in uf:
        uf.manage_delObjects('token_auth')
