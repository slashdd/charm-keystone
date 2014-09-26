import keystone_context as context
from mock import patch

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'determine_apache_port',
    'determine_api_port',
]


class TestKeystoneContexts(CharmTestCase):

    def setUp(self):
        super(TestKeystoneContexts, self).setUp(context, TO_PATCH)

    mod_ch_context = 'charmhelpers.contrib.openstack.context'

    @patch('%s.ApacheSSLContext.canonical_names' % (mod_ch_context))
    @patch('%s.ApacheSSLContext.configure_ca' % (mod_ch_context))
    @patch('%s.config' % (mod_ch_context))
    @patch('%s.is_clustered' % (mod_ch_context))
    @patch('%s.determine_apache_port' % (mod_ch_context))
    @patch('%s.determine_api_port' % (mod_ch_context))
    @patch('%s.unit_get' % (mod_ch_context))
    @patch('%s.https' % (mod_ch_context))
    def test_apache_ssl_context_service_enabled(self, mock_https,
                                                mock_unit_get,
                                                mock_determine_api_port,
                                                mock_determine_apache_port,
                                                mock_is_clustered,
                                                mock_config,
                                                mock_configure_ca,
                                                mock_cfg_canonical_names):
        mock_https.return_value = True
        mock_unit_get.return_value = '1.2.3.4'
        mock_determine_api_port.return_value = '12'
        mock_determine_apache_port.return_value = '34'
        mock_is_clustered.return_value = False

        ctxt = context.ApacheSSLContext()
        with patch.object(ctxt, 'enable_modules'):
            with patch.object(ctxt, 'configure_cert'):
                self.assertEquals(ctxt(), {'endpoints': [('1.2.3.4', '1.2.3.4',
                                                          34, 12)],
                                           'ext_ports': [34],
                                           'namespace': 'keystone'})
                self.assertTrue(mock_https.called)
                mock_unit_get.assert_called_with('private-address')

    @patch('%s.get_address_in_network' % (mod_ch_context))
    @patch('%s.ApacheSSLContext.canonical_names' % (mod_ch_context))
    @patch('%s.ApacheSSLContext.configure_ca' % (mod_ch_context))
    @patch('%s.config' % (mod_ch_context))
    @patch('%s.relation_ids' % (mod_ch_context))
    @patch('%s.unit_get' % (mod_ch_context))
    @patch('%s.related_units' % (mod_ch_context))
    @patch('%s.relation_get' % (mod_ch_context))
    @patch('%s.log' % (mod_ch_context))
    @patch('__builtin__.open')
    def test_haproxy_context_service_enabled(self, mock_open, mock_log,
                                             mock_relation_get,
                                             mock_related_units, mock_unit_get,
                                             mock_relation_ids, mock_config,
                                             mock_configure_ca,
                                             mock_cfg_canonical_names,
                                             mock_get_addr):
        mock_get_addr.return_value = "1.2.3.4"
        mock_relation_ids.return_value = ['identity-service:0', ]
        mock_unit_get.return_value = '1.2.3.4'
        mock_relation_get.return_value = '10.0.0.0'
        mock_related_units.return_value = ['unit/0', ]
        mock_config.side_effect = lambda args: False
        self.determine_apache_port.return_value = '34'

        ctxt = context.HAProxyContext()

        self.maxDiff = None
        self.assertEquals(
            ctxt(),
            {'listen_ports': {'admin_port': 'keystone',
                              'public_port': 'keystone'},
             'units': {'keystone': '1.2.3.4', 'unit-0': '10.0.0.0'},
             'local_host': '127.0.0.1',
             'haproxy_host': '0.0.0.0',
             'stat_port': ':8888',
             'service_ports': {'admin-port': ['keystone', '34'],
                               'public-port': ['keystone', '34']},
             'units': {'keystone': '1.2.3.4', 'unit-0': '10.0.0.0'}})
#        mock_unit_get.assert_called_with('private-address')
#        mock_relation_get.assert_called_with(
#            'private-address',
#            rid='identity-service:0',
#            unit='unit/0')
#        mock_open.assert_called_with('/etc/default/haproxy', 'w')
