from ftw.tokenauth import _
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
        raise Invalid(_('Invalid IP range: ${ip_range_error}',
                        mapping={'ip_range_error': str(exc)}))
    return True


class IKeyMetadataSchema(model.Schema):
    """
    """

    title = schema.TextLine(
        title=_(u'label_title', default=u'Title'),
    )

    key_id = schema.TextLine(
        title=_(u'label_key_id', default=u'Key ID'),
        readonly=True,
    )

    user_id = schema.TextLine(
        title=_(u'label_user_id', default=u'User ID'),
        readonly=True,
    )

    issued = schema.Datetime(
        title=_(u'label_issued', default=u'Issued'),
        readonly=True,
    )

    ip_range = schema.TextLine(
        title=_(u'label_ip_range', default=u'IP Range'),
        required=False,
        constraint=valid_ip_range,
        description=_(
            u'Allowed IP range specification in '
            u'<strong><a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">'  # noqa
            u'CIDR notation</a></strong>.'),
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
