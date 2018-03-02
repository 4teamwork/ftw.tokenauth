from datetime import datetime
from ftw.builder import Builder
from ftw.builder import create
from ftw.testbrowser import browsing
from ftw.testbrowser.exceptions import InsufficientPrivileges
from ftw.testbrowser.pages.statusmessages import assert_no_error_messages
from ftw.testbrowser.pages.statusmessages import error_messages
from ftw.testbrowser.pages.statusmessages import info_messages
from ftw.testbrowser.pages.z3cform import erroneous_fields
from ftw.testing import freeze
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.permissions import ManageOwnServiceKeys
from ftw.tokenauth.tests import FunctionalTestCase
from plone.app.testing import TEST_USER_ID
import json
import re
import transaction


class TestManageServiceKeysView(FunctionalTestCase):

    @browsing
    def test_manage_key_views_require_permission(self, browser):
        # Unmap the 'ftw.tokenauth: Manage own Service Keys'
        # permission from any roles
        self.portal.manage_permission(ManageOwnServiceKeys, roles=[])
        transaction.commit()

        browser.login()
        with self.assertRaises(InsufficientPrivileges):
            browser.login().open(view='@@manage-service-keys')

        with self.assertRaises(InsufficientPrivileges):
            browser.login().open(view='@@manage-service-keys-issue')

        with self.assertRaises(InsufficientPrivileges):
            browser.login().open(view='@@manage-service-keys-edit')

    @browsing
    def test_issuing_key_via_manage_service_keys_view(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()

        with freeze(datetime(2018, 1, 1, 15, 30)):
            browser.fill({
                'Title': 'My new key',
            }).find('Issue key').click()

        self.assertEqual(1, len(info_messages()))
        match = re.match('Key created: (.*)', info_messages()[0])
        self.assertTrue(match)
        displayed_key_id = match.group(1)

        storage = CredentialStorage(self.plugin)
        self.assertEqual(1, len(storage.list_service_keys(TEST_USER_ID)))
        service_key = storage.list_service_keys(TEST_USER_ID)[0]

        self.assertEqual(displayed_key_id, service_key['key_id'])
        self.assertEqual('My new key', service_key['title'])
        self.assertEqual(datetime(2018, 1, 1, 15, 30), service_key['issued'])
        self.assertEqual(TEST_USER_ID, service_key['user_id'])
        self.assertIn('client_id', service_key)
        self.assertIn('public_key', service_key)

    @browsing
    def test_issuing_key_displays_private_key_for_download(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()

        browser.fill({
            'Title': 'My new key',
        }).find('Issue key').click()

        self.assertEqual(1, len(info_messages()))
        match = re.match('Key created: (.*)', info_messages()[0])
        self.assertTrue(match)

        storage = CredentialStorage(self.plugin)
        self.assertEqual(1, len(storage.list_service_keys(TEST_USER_ID)))
        key = storage.list_service_keys(TEST_USER_ID)[0]

        self.assertTrue('Download your Service Key' in browser.contents)
        self.assertTrue('My new key' in browser.contents)

        json_keyfile = browser.css('.json-keyfile').first
        keyfile_data = json.loads(json_keyfile.text)
        self.assertEquals(
            set(['key_id', 'client_id', 'issued', 'user_id', 'token_uri',
                 'private_key']),
            set(keyfile_data.keys()))

        # TODO: Assert on private key contents, if possible
        self.assertEqual(
            key['key_id'], keyfile_data['key_id'])
        self.assertEqual(
            key['issued'].isoformat(), keyfile_data['issued'])
        self.assertEqual(
            TEST_USER_ID, keyfile_data['user_id'])
        self.assertEqual(
            'http://nohost/plone/@@oauth2-token', keyfile_data['token_uri'])

    @browsing
    def test_issuing_key_without_title_is_not_allowed(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()
        browser.find('Issue key').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'Title':
                ['Required input is missing.']},
            erroneous_fields(browser.forms['form']))

        storage = CredentialStorage(self.plugin)
        self.assertEqual(0, len(storage.list_service_keys(TEST_USER_ID)))

    @browsing
    def test_issue_key_form_handles_cancelling(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()
        browser.find('Cancel').click()

        assert_no_error_messages()
        self.assertEqual(['Key creation cancelled.'], info_messages())

    @browsing
    def test_lists_issued_keys(self, browser):
        with freeze(datetime(2017, 1, 1, 15, 30)):
            create(Builder('service_key')
                   .having(title='Key 1'))

        with freeze(datetime(2018, 5, 5, 12, 45)):
            create(Builder('service_key')
                   .having(title='Key 2'))
        transaction.commit()

        storage = CredentialStorage(self.plugin)
        keys = storage.list_service_keys(TEST_USER_ID)
        client_ids = [k['client_id'] for k in keys]

        browser.login().open(view='@@manage-service-keys')
        table = browser.css('#table-service-keys').first.lists()

        self.assertEquals(
            ['', 'Title', 'Client-ID', 'Issued', ''],
            table[0])
        self.assertEquals(
            ['', 'Key 1', client_ids[0], 'Jan 01, 2017 03:30 PM', 'Edit'],  # noqa
            table[1])
        self.assertEquals(
            ['', 'Key 2', client_ids[1], 'May 05, 2018 12:45 PM', 'Edit'],  # noqa
            table[2])


class TestEditServiceKeysView(FunctionalTestCase):

    @browsing
    def test_editing_key_metadata(self, browser):
        create(Builder('service_key'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.fill({
            'Title': 'New title',
        }).find('Apply').click()

        self.assertEqual(['Data successfully updated.'], info_messages())

        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(TEST_USER_ID)
        self.assertEqual(1, len(users_keys))
        key = users_keys[0]

        self.assertEqual('New title', key['title'])

    @browsing
    def test_edit_key_form_validates_constraints(self, browser):
        create(Builder('service_key')
               .having(title='Some key'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.fill({
            'Title': '',
        }).find('Apply').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'Title':
                ['Required input is missing.']},
            erroneous_fields(browser.forms['form']))

        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(TEST_USER_ID)
        self.assertEqual(1, len(users_keys))
        service_key = users_keys[0]

        # Key shouldn't have been updated
        self.assertEqual('Some key', service_key['title'])

    @browsing
    def test_edit_key_form_retains_widget_values_on_error(self, browser):
        create(Builder('service_key')
               .having(title='Some key'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.fill({
            'Title': '',
        }).find('Apply').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'Title':
                ['Required input is missing.']},
            erroneous_fields(browser.forms['form']))

        form = browser.forms['form']
        self.assertEquals(
            [('form.widgets.title', ''),
             ('form.buttons.cancel', 'Cancel'),
             ('form.buttons.apply', 'Apply')],
            form.values.items())

    @browsing
    def test_edit_key_form_handles_no_changes_being_made(self, browser):
        create(Builder('service_key'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.find('Apply').click()
        self.assertEqual(['No changes were applied.'], info_messages())

    @browsing
    def test_edit_key_form_handles_cancelling_edit(self, browser):
        create(Builder('service_key'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.find('Cancel').click()
        self.assertEqual(['Edit cancelled'], info_messages())
        self.assertTrue(browser.url.endswith('@@manage-service-keys'))
