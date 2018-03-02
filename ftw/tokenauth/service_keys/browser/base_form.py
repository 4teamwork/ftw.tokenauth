from plone import api
from plone.supermodel import model
from z3c.form.form import Form
from zope import schema


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
