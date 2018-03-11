from collections import OrderedDict
from ftw.tokenauth import _
from ftw.tokenauth.service_keys.browser.base_form import BaseForm
from ftw.tokenauth.service_keys.browser.base_form import IKeyMetadataSchema
from plone import api
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from z3c.form import button
from z3c.form.field import Fields
from zope.globalrequest import getRequest
import json


def create_json_keyfile(private_key, service_key):
    """Create a serialized JSON string with the service_key ready for download.
    """
    keydata = OrderedDict([
        ('key_id', service_key['key_id']),
        ('client_id', service_key['client_id']),
        ('user_id', service_key['user_id']),
        ('issued', service_key['issued'].isoformat()),
        ('token_uri', service_key['token_uri']),
        ('private_key', private_key),
    ])
    keyfile = json.dumps(
        keydata, indent=4, separators=(',', ': '))
    return keyfile


class IssueKeyForm(BaseForm):

    label = _(u'Issue Service Key')
    description = _(u'Issue a key to be used for authentication '
                    u'by a service application')

    fields = Fields(IKeyMetadataSchema).select('title', 'ip_range')

    download_key_template = ViewPageTemplateFile('download_key.pt')

    @button.buttonAndHandler(_(u'Issue key'), name='save')
    def handleApply(self, action):
        data, errors = self.extractData()
        if errors:
            self.status = self.formErrorsMessage
            return

        user_id = api.user.get_current().id

        private_key, service_key = self.get_plugin().issue_keypair(
            user_id, data['title'], data['ip_range'])

        self._key_issued = True
        self._generated_private_key = private_key
        self._generated_service_key = service_key

        msg = _('Key created: ${key_id}',
                mapping={'key_id': service_key['key_id']})
        api.portal.show_message(msg, getRequest())

    @button.buttonAndHandler(_(u'Cancel'), name='cancel')
    def handleCancel(self, action):
        api.portal.show_message(
            _(u'Key creation cancelled.'), getRequest())
        return self.request.RESPONSE.redirect(self.main_url)

    def render(self):
        if getattr(self, '_key_issued', False) is True:
            # We carry over the newly issued key in these attributes on the
            # view to offer the private key for download exactly once.
            private_key = self._generated_private_key
            service_key = self._generated_service_key

            del self._generated_private_key

            json_keyfile = create_json_keyfile(private_key, service_key)
            template_vars = {
                'key_id': service_key['key_id'],
                'title': service_key['title'],
                'json_keyfile': json_keyfile,
            }
            return self.download_key_template(**template_vars)

        return super(IssueKeyForm, self).render()
