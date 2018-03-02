from ftw.tokenauth.pas.ip_range import InvalidIPRangeSpecification
from ftw.tokenauth.pas.ip_range import parse_ip_range
from plone import api
from plone.supermodel import model
from z3c.form.form import Form
from zope import schema
from zope.interface import Invalid


def valid_ip_range(value):
    """Form validator that checks for a valid IP range specification.
    """
    try:
        parse_ip_range(value)
    except InvalidIPRangeSpecification as exc:
        raise Invalid('Invalid IP range: %s' % str(exc))
    return True


class IKeyMetadataSchema(model.Schema):
    """
    """

    title = schema.TextLine(
        title=u"Title",
    )

    key_id = schema.TextLine(
        title=u"Key ID",
        readonly=True,
    )

    user_id = schema.TextLine(
        title=u"User ID",
        readonly=True,
    )

    issued = schema.Datetime(
        title=u"Issued",
        readonly=True,
    )

    ip_range = schema.TextLine(
        title=u"IP Range",
        required=False,
        constraint=valid_ip_range,
    )


class BaseForm(Form):

    ignoreContext = True

    @property
    def portal_url(self):
        return api.portal.get().absolute_url()

    @property
    def main_url(self):
        return self.portal_url + '/@@manage-service-keys'

    def get_plugin(self):
        acl_users = api.portal.get().acl_users
        return acl_users['token_auth']

    def update(self):
        self.request.set('disable_border', True)
        super(BaseForm, self).update()
