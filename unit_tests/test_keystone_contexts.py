import keystone_context as context
from mock import patch

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'determine_api_port',
]


class TestKeystoneContexts(CharmTestCase):

    def setUp(self):
        super(TestKeystoneContexts, self).setUp(context, TO_PATCH)

    @patch('charmhelpers.contrib.openstack.context.is_clustered')
    @patch('charmhelpers.contrib.openstack.context.determine_apache_port')
    @patch('charmhelpers.contrib.openstack.context.determine_api_port')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.https')
    def test_apache_ssl_context_service_enabled(self, mock_https,
                                                mock_unit_get,
                                                mock_determine_api_port,
                                                mock_determine_apache_port,
                                                mock_is_clustered):
        mock_https.return_value = True
        mock_unit_get.return_value = '1.2.3.4'
        mock_determine_api_port.return_value = '12'
        mock_determine_apache_port.return_value = '34'
        mock_is_clustered.return_value = False

        ctxt = context.ApacheSSLContext()
        with patch.object(ctxt, 'enable_modules'):
            with patch.object(ctxt, 'configure_cert'):
                self.assertEquals(ctxt(), {'endpoints': [(34, 12)],
                                           'private_address': '1.2.3.4',
                                           'namespace': 'keystone'})
                self.assertTrue(mock_https.called)
                mock_unit_get.assert_called_with('private-address')

    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.related_units')
    @patch('charmhelpers.contrib.openstack.context.relation_get')
    @patch('charmhelpers.contrib.openstack.context.log')
    @patch('__builtin__.open')
    def test_haproxy_context_service_enabled(
        self, mock_open, mock_log, mock_relation_get, mock_related_units,
            mock_unit_get, mock_relation_ids, mock_config):
        mock_relation_ids.return_value = ['identity-service:0', ]
        mock_unit_get.return_value = '1.2.3.4'
        mock_relation_get.return_value = '10.0.0.0'
        mock_related_units.return_value = ['unit/0', ]
        mock_config.side_effect = [False, None, False]

        ctxt = context.HAProxyContext()

        self.maxDiff = None
        self.assertEquals(
            ctxt(),
            {'listen_ports': {'admin_port': 'keystone',
                              'public_port': 'keystone'},
             'units': {'keystone': '1.2.3.4', 'unit-0': '10.0.0.0'},
             'local_host': '127.0.0.1',
             'haproxy_host': '0.0.0.0',
             'stat_port': ':8888'})
#        mock_unit_get.assert_called_with('private-address')
#        mock_relation_get.assert_called_with(
#            'private-address',
#            rid='identity-service:0',
#            unit='unit/0')
#        mock_open.assert_called_with('/etc/default/haproxy', 'w')
