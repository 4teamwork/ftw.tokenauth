from ftw.tokenauth.service_keys.browser.base_form import valid_ip_range
from zope.interface import Invalid
import unittest


class TestIPRangeFormValidator(unittest.TestCase):

    def test_single_ipv4_address_is_valid(self):
        self.assertTrue(valid_ip_range('192.168.0.0'))

    def test_single_ipv4_cidr_network_is_valid(self):
        self.assertTrue(valid_ip_range('192.168.0.0/16'))

    def test_invalid_ip_address_is_rejected(self):
        with self.assertRaises(Invalid):
            valid_ip_range('500.500.0.0')
