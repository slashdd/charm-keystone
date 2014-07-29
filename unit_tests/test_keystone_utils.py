from mock import patch, call, MagicMock
from test_utils import CharmTestCase
import os
import manager

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config:
    import keystone_utils as utils

import keystone_hooks as hooks

TO_PATCH = [
    'api_port',
    'config',
    'create_user',
    'os_release',
    'log',
    'get_ca',
    'create_role',
    'create_service_entry',
    'create_endpoint_template',
    'get_admin_token',
    'get_local_endpoint',
    'get_requested_roles',
    'get_service_password',
    'get_os_codename_install_source',
    'grant_role',
    'configure_installation_source',
    'eligible_leader',
    'https',
    'is_clustered',
    'service_stop',
    'service_start',
    'relation_get',
    'relation_set',
    'https',
    # generic
    'apt_update',
    'apt_upgrade',
    'apt_install',
    'subprocess',
    'time',
    'pwgen',
    # openstack.ip
    'resolve_address',
]


class TestKeystoneUtils(CharmTestCase):

    def setUp(self):
        super(TestKeystoneUtils, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

        self.ctxt = MagicMock()
        self.rsc_map = {
            '/etc/keystone/keystone.conf': {
                'services': ['keystone'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend.conf': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            }
        }

    @patch('charmhelpers.contrib.openstack.templating.OSConfigRenderer')
    @patch('os.path.exists')
    @patch.object(utils, 'resource_map')
    def test_register_configs_apache(self, resource_map, exists, renderer):
        exists.return_value = False
        self.os_release.return_value = 'havana'
        fake_renderer = MagicMock()
        fake_renderer.register = MagicMock()
        renderer.return_value = fake_renderer

        resource_map.return_value = self.rsc_map
        utils.register_configs()
        renderer.assert_called_with(
            openstack_release='havana', templates_dir='templates/')

        ex_reg = [
            call('/etc/keystone/keystone.conf', [self.ctxt]),
            call(
                '/etc/apache2/sites-available/openstack_https_frontend',
                [self.ctxt]),
            call(
                '/etc/apache2/sites-available/openstack_https_frontend.conf',
                [self.ctxt]),
        ]
        self.assertEquals(fake_renderer.register.call_args_list, ex_reg)

    def test_determine_ports(self):
        self.test_config.set('admin-port', '80')
        self.test_config.set('service-port', '81')
        result = utils.determine_ports()
        self.assertEquals(result, ['80', '81'])

    def test_determine_packages(self):
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + ['keystone', 'haproxy', 'apache2']
        self.assertEquals(set(ex), set(result))

    @patch.object(hooks, 'CONFIGS')
    @patch.object(utils, 'determine_packages')
    @patch.object(utils, 'migrate_database')
    def test_openstack_upgrade_leader(
            self, migrate_database, determine_packages, configs):
        self.test_config.set('openstack-origin', 'precise')
        determine_packages.return_value = []
        self.eligible_leader.return_value = True

        utils.do_openstack_upgrade(configs)

        self.get_os_codename_install_source.assert_called_with('precise')
        self.configure_installation_source.assert_called_with('precise')
        self.assertTrue(self.apt_update.called)

        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_upgrade.assert_called_with(
            options=dpkg_opts,
            fatal=True,
            dist=True)
        self.apt_install.assert_called_with(
            packages=[],
            options=dpkg_opts,
            fatal=True)

        self.assertTrue(configs.set_release.called)
        self.assertTrue(configs.write_all.called)
        self.assertTrue(migrate_database.called)

    def test_migrate_database(self):
        utils.migrate_database()

        self.service_stop.assert_called_with('keystone')
        cmd = ['sudo', '-u', 'keystone', 'keystone-manage', 'db_sync']
        self.subprocess.check_output.assert_called_with(cmd)
        self.service_start.assert_called_wkth('keystone')

    @patch.object(utils, 'b64encode')
    def test_add_service_to_keystone_clustered_https_none_values(
            self, b64encode):
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'
        self.resolve_address.return_value = '10.10.10.10'
        self.https.return_value = True
        self.test_config.set('https-service-endpoints', 'True')
        self.test_config.set('vip', '10.10.10.10')
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        b64encode.return_value = 'certificate'
        self.get_requested_roles.return_value = ['role1', ]

        self.relation_get.return_value = {'service': 'keystone',
                                          'region': 'RegionOne',
                                          'public_url': 'None',
                                          'admin_url': '10.0.0.2',
                                          'internal_url': '192.168.1.2'}

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        self.assertTrue(self.https.called)
        self.assertTrue(self.create_role.called)

        relation_data = {'auth_host': '10.10.10.10',
                         'service_host': '10.10.10.10',
                         'auth_protocol': 'https',
                         'service_protocol': 'https',
                         'auth_port': 80,
                         'service_port': 81,
                         'https_keystone': 'True',
                         'ca_cert': 'certificate'}
        self.relation_set.assert_called_with(
            relation_id=relation_id,
            **relation_data)

    @patch.object(utils, 'ensure_valid_service')
    @patch.object(utils, 'add_endpoint')
    @patch.object(manager, 'KeystoneManager')
    def test_add_service_to_keystone_no_clustered_no_https_complete_values(
            self, KeystoneManager, add_endpoint, ensure_valid_service):
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'
        self.get_admin_token.return_value = 'token'
        self.get_service_password.return_value = 'password'
        self.test_config.set('service-tenant', 'tenant')
        self.test_config.set('admin-role', 'admin')
        self.get_requested_roles.return_value = ['role1', ]
        self.resolve_address.return_value = '10.0.0.3'
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        self.is_clustered.return_value = False
        self.https.return_value = False
        self.test_config.set('https-service-endpoints', 'False')
        self.get_local_endpoint.return_value = 'http://localhost:80/v2.0/'

        mock_keystone = MagicMock()
        mock_keystone.resolve_tenant_id.return_value = 'tenant_id'
        KeystoneManager.return_value = mock_keystone

        self.relation_get.return_value = {'service': 'keystone',
                                          'region': 'RegionOne',
                                          'public_url': '10.0.0.1',
                                          'admin_url': '10.0.0.2',
                                          'internal_url': '192.168.1.2'}

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        ensure_valid_service.assert_called_with('keystone')
        add_endpoint.assert_called_with(region='RegionOne', service='keystone',
                                        publicurl='10.0.0.1',
                                        adminurl='10.0.0.2',
                                        internalurl='192.168.1.2')
        self.assertTrue(self.get_admin_token.called)
        self.get_service_password.assert_called_with('keystone')
        self.create_user.assert_called_with('keystone', 'password', 'tenant')
        self.grant_role.assert_called_with('keystone', 'admin', 'tenant')
        self.create_role.assert_called_with('role1', 'keystone', 'tenant')

        relation_data = {'admin_token': 'token', 'service_port': 81,
                         'auth_port': 80, 'service_username': 'keystone',
                         'service_password': 'password',
                         'service_tenant': 'tenant',
                         'https_keystone': 'False',
                         'ssl_cert': '', 'ssl_key': '',
                         'ca_cert': '', 'auth_host': '10.0.0.3',
                         'service_host': '10.0.0.3',
                         'auth_protocol': 'http', 'service_protocol': 'http',
                         'service_tenant_id': 'tenant_id'}
        self.relation_set.assert_called_with(
            relation_id=relation_id,
            **relation_data)

    @patch.object(utils, 'ensure_valid_service')
    @patch.object(utils, 'add_endpoint')
    @patch.object(manager, 'KeystoneManager')
    def test_add_service_to_keystone_nosubset(
            self, KeystoneManager, add_endpoint, ensure_valid_service):
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'

        self.relation_get.return_value = {'ec2_service': 'nova',
                                          'ec2_region': 'RegionOne',
                                          'ec2_public_url': '10.0.0.1',
                                          'ec2_admin_url': '10.0.0.2',
                                          'ec2_internal_url': '192.168.1.2'}
        self.get_local_endpoint.return_value = 'http://localhost:80/v2.0/'
        KeystoneManager.resolve_tenant_id.return_value = 'tenant_id'

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        ensure_valid_service.assert_called_with('nova')
        add_endpoint.assert_called_with(region='RegionOne', service='nova',
                                        publicurl='10.0.0.1',
                                        adminurl='10.0.0.2',
                                        internalurl='192.168.1.2')

    def test_ensure_valid_service_incorrect(self):
        utils.ensure_valid_service('fakeservice')
        self.log.assert_called_with("Invalid service requested: 'fakeservice'")
        self.relation_set.assert_called_with(admin_token=-1)

    def test_add_endpoint(self):
        publicurl = '10.0.0.1'
        adminurl = '10.0.0.2'
        internalurl = '10.0.0.3'
        utils.add_endpoint(
            'RegionOne',
            'nova',
            publicurl,
            adminurl,
            internalurl)
        self.create_service_entry.assert_called_with(
            'nova',
            'compute',
            'Nova Compute Service')
        self.create_endpoint_template.asssert_called_with(
            region='RegionOne', service='nova',
            publicurl=publicurl, adminurl=adminurl,
            internalurl=internalurl)
