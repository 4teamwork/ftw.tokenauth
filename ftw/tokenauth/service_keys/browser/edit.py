from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.service_keys.browser.base_form import BaseForm
from ftw.tokenauth.service_keys.browser.base_form import IKeyMetadataSchema
from plone import api
from z3c.form import button
from z3c.form.field import Fields
from z3c.form.i18n import MessageFactory as Z3CFormMF
from z3c.form.interfaces import IDataConverter
from z3c.form.interfaces import NOT_CHANGED
from zope.globalrequest import getRequest


class EditKeyForm(BaseForm):

    label = u'Edit Service Key'
    description = u'Edit service key'

    successMessage = Z3CFormMF('Data successfully updated.')
    noChangesMessage = Z3CFormMF('No changes were applied.')

    fields = Fields(IKeyMetadataSchema)

    def updateWidgets(self, *args, **kwargs):
        super(EditKeyForm, self).updateWidgets(*args, **kwargs)

        # Hack to retain widget values on validation error
        if 'form.buttons.apply' not in self.request:
            # Prefill form
            key = self.get_key()
            for widget in self.widgets.values():
                name = widget.field.getName()
                value = key[name]
                converter = IDataConverter(widget)
                widget.value = converter.toWidgetValue(value)

    def get_key(self):
        key_id = self.request.form['key_id']
        storage = CredentialStorage(self.get_plugin())
        key = storage.get_service_key(key_id)
        return key

    def action(self):
        """Redefine <form action=''> attribute.
        """
        return self.request.getURL() + '?key_id=%s' % self.request['key_id']

    def field_value_has_changed(self, field, new_value, key):
        name = field.getName()
        old_value = key[name]
        return old_value != new_value

    def applyChanges(self, data):
        # Based on z3c.form.form.applyChanges, but without firing events
        key = self.get_key()

        changes = {}
        for name, field in self.fields.items():
            # If the field is not in the data, then go on to the next one
            try:
                new_value = data[name]
            except KeyError:
                continue
            # If the value is NOT_CHANGED, ignore it, since the
            # widget/converter sent a strong message not to do so.
            if new_value is NOT_CHANGED:
                continue
            if self.field_value_has_changed(field.field, new_value, key):
                # Only update the data if it changed
                # TODO: Should we possibly be using toFieldValue here?
                key[name] = new_value

                # Record the change using information required later
                changes.setdefault(field.interface, []).append(name)

        return changes

    @button.buttonAndHandler(Z3CFormMF('Apply'), name='apply')
    def handleApply(self, action):
        data, errors = self.extractData()
        if errors:
            self.status = self.formErrorsMessage
            return
        changes = self.applyChanges(data)
        if changes:
            api.portal.show_message(self.successMessage, getRequest())
        else:
            api.portal.show_message(self.noChangesMessage, getRequest())
        return self.request.RESPONSE.redirect(self.main_url)

    @button.buttonAndHandler(u'Cancel')
    def handleCancel(self, action):
        api.portal.show_message('Edit cancelled', getRequest())
        return self.request.RESPONSE.redirect(self.main_url)
