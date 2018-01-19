# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from mock import patch, MagicMock
with patch('charmhelpers.contrib.openstack.'
           'utils.snap_install_requested') as snap_install_requested:
    snap_install_requested.return_value = False
    import keystone_utils  # noqa
    import keystone_context as context

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config',
    'determine_apache_port',
    'determine_api_port',
]


class TestKeystoneContexts(CharmTestCase):

    def setUp(self):
        super(TestKeystoneContexts, self).setUp(context, TO_PATCH)

    def test_is_cert_provided_in_config(self):
        config = {'ssl_cert': 'somecert', 'ssl_key': 'greatkey'}

        def fake_config(key):
            return config.get(key)

        self.config.side_effect = fake_config
        self.assertTrue(context.is_cert_provided_in_config())

        del config['ssl_cert']
        self.assertFalse(context.is_cert_provided_in_config())

    @patch.object(context, 'mkdir')
    @patch('keystone_utils.get_ca')
    @patch('keystone_utils.ensure_permissions')
    @patch('keystone_utils.determine_ports', lambda: None)
    @patch('keystone_utils.is_ssl_cert_master', lambda: False)
    @patch.object(context, 'is_cert_provided_in_config', lambda: False)
    @patch.object(context, 'log', lambda *args, **kwargs: None)
    def test_apache_ssl_context_ssl_not_master(self, mock_ensure_permissions,
                                               mock_get_ca, mock_mkdir):
        context.ApacheSSLContext().configure_cert('foo')
        context.ApacheSSLContext().configure_ca()
        self.assertTrue(mock_mkdir.called)
        self.assertTrue(mock_ensure_permissions.called)
        self.assertFalse(mock_get_ca.called)

    @patch('keystone_utils.ensure_permissions')
    @patch.object(context, 'install_ca_cert')
    @patch.object(context, 'b64decode')
    @patch.object(context, 'mkdir', lambda *args: None)
    @patch('keystone_utils.get_ca', lambda: None)
    @patch('keystone_utils.determine_ports', lambda: None)
    @patch('keystone_utils.is_ssl_cert_master', lambda: True)
    @patch.object(context, 'log', lambda *args, **kwargs: None)
    def test_apache_ssl_context_ssl_configure_ca(self, mock_b64decode,
                                                 mock_install_ca_cert,
                                                 mock_ensure_permissions):
        config = {'ssl_cert': 'somecert', 'ssl_key': 'greatkey'}

        def fake_config(key):
            return config.get(key)

        self.config.side_effect = fake_config

        context.ApacheSSLContext().configure_ca()
        self.assertFalse(mock_b64decode.called)
        self.assertFalse(mock_install_ca_cert.called)
        self.assertFalse(mock_ensure_permissions.called)

        config['ssl_ca'] = 'foofoofalalala'
        context.ApacheSSLContext().configure_ca()
        self.assertTrue(mock_b64decode.called)
        self.assertTrue(mock_install_ca_cert.called)
        self.assertTrue(mock_ensure_permissions.called)

    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.service_name')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch('keystone_utils.determine_ports')
    @patch('keystone_utils.is_ssl_cert_master')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.is_clustered')
    @patch('charmhelpers.contrib.openstack.context.determine_apache_port')
    @patch('charmhelpers.contrib.openstack.context.determine_api_port')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.https')
    def test_apache_ssl_context_service_enabled(self, mock_https,
                                                mock_unit_get,
                                                mock_determine_api_port,
                                                mock_determine_apache_port,
                                                mock_is_clustered,
                                                mock_config,
                                                mock_is_ssl_cert_master,
                                                mock_determine_ports,
                                                mock_ip_config,
                                                mock_service_name,
                                                mock_ip_unit_get,
                                                mock_rel_ids,
                                                ):
        mock_is_ssl_cert_master.return_value = True
        mock_https.return_value = True
        mock_unit_get.return_value = '1.2.3.4'
        mock_ip_unit_get.return_value = '1.2.3.4'
        mock_determine_api_port.return_value = '12'
        mock_determine_apache_port.return_value = '34'
        mock_is_clustered.return_value = False
        mock_config.return_value = None
        mock_ip_config.return_value = None
        mock_determine_ports.return_value = ['12']

        ctxt = context.ApacheSSLContext()
        ctxt.enable_modules = MagicMock()
        ctxt.configure_cert = MagicMock()
        ctxt.configure_ca = MagicMock()
        ctxt.canonical_names = MagicMock()
        self.assertEqual(ctxt(), {'endpoints': [('1.2.3.4',
                                                 '1.2.3.4',
                                                 34, 12)],
                                  'namespace': 'keystone',
                                  'ext_ports': [34]})
        self.assertTrue(mock_https.called)
        mock_unit_get.assert_called_with('private-address')

    @patch('charmhelpers.contrib.openstack.context.get_relation_ip')
    @patch('charmhelpers.contrib.openstack.context.mkdir')
    @patch('keystone_utils.api_port')
    @patch('charmhelpers.contrib.openstack.context.get_netmask_for_address')
    @patch('charmhelpers.contrib.openstack.context.get_address_in_network')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.related_units')
    @patch('charmhelpers.contrib.openstack.context.relation_get')
    @patch('charmhelpers.contrib.openstack.context.log')
    @patch('charmhelpers.contrib.openstack.context.kv')
    @patch('__builtin__.open')
    def test_haproxy_context_service_enabled(
        self, mock_open, mock_kv, mock_log, mock_relation_get,
            mock_related_units, mock_unit_get, mock_relation_ids, mock_config,
            mock_get_address_in_network, mock_get_netmask_for_address,
            mock_api_port, mock_mkdir, mock_get_relation_ip):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        mock_relation_ids.return_value = ['identity-service:0', ]
        mock_unit_get.return_value = '1.2.3.4'
        mock_get_relation_ip.return_value = '1.2.3.4'
        mock_relation_get.return_value = '10.0.0.0'
        mock_related_units.return_value = ['unit/0', ]
        mock_config.return_value = None
        mock_get_address_in_network.return_value = None
        mock_get_netmask_for_address.return_value = '255.255.255.0'
        self.determine_apache_port.return_value = '34'
        mock_api_port.return_value = '12'
        mock_kv().get.return_value = 'abcdefghijklmnopqrstuvwxyz123456'

        ctxt = context.HAProxyContext()

        self.maxDiff = None
        self.assertEqual(
            ctxt(),
            {'listen_ports': {'admin_port': '12',
                              'public_port': '12'},
             'local_host': '127.0.0.1',
             'haproxy_host': '0.0.0.0',
             'stat_port': '8888',
             'stat_password': 'abcdefghijklmnopqrstuvwxyz123456',
             'service_ports': {'admin-port': ['12', '34'],
                               'public-port': ['12', '34']},
             'default_backend': '1.2.3.4',
             'ipv6_enabled': True,
             'frontends': {'1.2.3.4': {
                 'network': '1.2.3.4/255.255.255.0',
                 'backends': {
                     'keystone': '1.2.3.4',
                     'unit-0': '10.0.0.0'
                 }
             }}
             }
        )

    @patch.object(context, 'config')
    def test_keystone_logger_context(self, mock_config):
        ctxt = context.KeystoneLoggingContext()

        mock_config.return_value = None
        self.assertEqual({'log_level': None,
                          'log_file': '/var/log/keystone/keystone.log'},
                         ctxt())

    @patch.object(context, 'is_elected_leader')
    def test_token_flush_context(self, mock_is_elected_leader):
        ctxt = context.TokenFlushContext()

        mock_is_elected_leader.return_value = False
        self.assertEqual({'token_flush': False}, ctxt())

        mock_is_elected_leader.return_value = True
        self.assertEqual({'token_flush': True}, ctxt())
