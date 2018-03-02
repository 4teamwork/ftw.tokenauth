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

        with self.assertRaises(InsufficientPrivileges):
            browser.login().open(view='@@manage-service-keys-logs')

    @browsing
    def test_issuing_key_via_manage_service_keys_view(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()

        with freeze(datetime(2018, 1, 1, 15, 30)):
            browser.fill({
                'Title': 'My new key',
                'IP Range': '192.168.0.0/16',
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
        self.assertEqual('192.168.0.0/16', service_key['ip_range'])
        self.assertIn('public_key', service_key)

    @browsing
    def test_issuing_key_displays_private_key_for_download(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()

        browser.fill({
            'Title': 'My new key',
            'IP Range': '192.168.0.0/16',
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
    def test_issuing_key_without_ip_range_is_allowed(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()

        browser.fill({'Title': 'Key without IP range'})
        browser.find('Issue key').click()

        assert_no_error_messages()

        storage = CredentialStorage(self.plugin)
        self.assertEqual(1, len(storage.list_service_keys(TEST_USER_ID)))
        key = storage.list_service_keys(TEST_USER_ID)[0]

        self.assertEqual('Key without IP range', key['title'])
        self.assertEqual(None, key['ip_range'])

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
    def test_issuing_key_with_invalid_ip_range_is_rejected(self, browser):
        browser.login().open(view='@@manage-service-keys')
        browser.find('Issue new service key').click()
        browser.fill({
            'Title': 'Key with invalid IP range',
            'IP Range': '192.168.5.5/16',
        }).find('Issue key').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'IP Range':
                ['Invalid IP range: 192.168.5.5/16 has host bits set']},
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
                   .having(title='Key 2',
                           ip_range='192.168.0.0/16'))
        transaction.commit()

        storage = CredentialStorage(self.plugin)
        keys = storage.list_service_keys(TEST_USER_ID)
        client_ids = [k['client_id'] for k in keys]

        browser.login().open(view='@@manage-service-keys')
        table = browser.css('#table-service-keys').first.lists()

        self.assertEquals(
            ['', 'Title', 'Client-ID', 'IP Range', 'Issued', 'Last Used', ''],
            table[0])
        self.assertEquals(
            ['', 'Key 1', client_ids[0], '', 'Jan 01, 2017 03:30 PM', '', 'Edit'],  # noqa
            table[1])
        self.assertEquals(
            ['', 'Key 2', client_ids[1], '192.168.0.0/16', 'May 05, 2018 12:45 PM', '', 'Edit'],  # noqa
            table[2])

    @browsing
    def test_revoking_key_via_manage_service_keys_view(self, browser):
        service_key = create(Builder('service_key')
                             .having(title='My key'))
        transaction.commit()

        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(TEST_USER_ID)
        self.assertEqual(1, len(users_keys))
        stored_service_key = users_keys[0]

        # Guard assertion - make sure the issued key is actually in storage
        self.assertEqual(
            service_key['key_id'], stored_service_key['key_id'])
        self.assertEqual(
            service_key['public_key'], stored_service_key['public_key'])

        # Revoke the key
        browser.login().open(view='@@manage-service-keys')
        browser.fill({'My key': True})
        browser.find('Revoke selected keys').click()

        # Got removed from storage
        self.assertEqual([], storage.list_service_keys(TEST_USER_ID))


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
            'IP Range': '10.0.0.0/24',
        }).find('Apply').click()

        self.assertEqual(['Data successfully updated.'], info_messages())

        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(TEST_USER_ID)
        self.assertEqual(1, len(users_keys))
        key = users_keys[0]

        self.assertEqual('New title', key['title'])
        self.assertEqual('10.0.0.0/24', key['ip_range'])

    @browsing
    def test_edit_key_form_validates_constraints(self, browser):
        create(Builder('service_key')
               .having(title='Some key',
                       ip_range='192.168.0.0/16'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.fill({
            'Title': '',
            'IP Range': '10.0.5.5/24',
        }).find('Apply').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'IP Range':
                ['Invalid IP range: 10.0.5.5/24 has host bits set'],
             'Title':
                ['Required input is missing.']},
            erroneous_fields(browser.forms['form']))

        storage = CredentialStorage(self.plugin)
        users_keys = storage.list_service_keys(TEST_USER_ID)
        self.assertEqual(1, len(users_keys))
        service_key = users_keys[0]

        # Key shouldn't have been updated
        self.assertEqual('Some key', service_key['title'])
        self.assertEqual('192.168.0.0/16', service_key['ip_range'])

    @browsing
    def test_edit_key_form_retains_widget_values_on_error(self, browser):
        create(Builder('service_key')
               .having(title='Some key',
                       ip_range='192.168.0.0/16'))
        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        edit_link = browser.css('#table-service-keys tr')[-1].find('Edit')
        edit_link.click()

        browser.fill({
            'Title': '',
            'IP Range': '10.0.5.5/24',
        }).find('Apply').click()

        self.assertEqual(['There were some errors.'], error_messages())

        self.assertEqual(
            {'IP Range':
                ['Invalid IP range: 10.0.5.5/24 has host bits set'],
             'Title':
                ['Required input is missing.']},
            erroneous_fields(browser.forms['form']))

        form = browser.forms['form']
        self.assertEquals(
            [('form.widgets.ip_range', '10.0.5.5/24'),
             ('form.widgets.title', ''),
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


class TestUsageLogsView(FunctionalTestCase):

    @browsing
    def test_lists_usage_logs(self, browser):
        # Create a service key and issue two access tokens with it
        service_key = create(Builder('service_key'))
        self.request._client_addr = '10.0.0.77'

        with freeze(datetime(2018, 1, 1, 15, 30)):
            create(Builder('access_token')
                   .from_key(service_key))

        with freeze(datetime(2018, 1, 5, 12, 45)):
            create(Builder('access_token')
                   .from_key(service_key))

        transaction.commit()

        browser.login().open(view='@@manage-service-keys')
        keys_table = browser.css('#table-service-keys').first
        self.assertEqual(
            ['Jan 05, 2018 12:45 PM'],
            keys_table.column('Last Used', head=False)
        )

        logs_link = keys_table.find('Jan 05, 2018 12:45 PM').css('a').first
        logs_link.click()

        logs_table = browser.css('#table-usage-logs').first
        self.assertEqual(
            [{'IP Address': '10.0.0.77', 'Time': 'Jan 01, 2018 03:30 PM'},
             {'IP Address': '10.0.0.77', 'Time': 'Jan 05, 2018 12:45 PM'}],
            logs_table.dicts()
        )
