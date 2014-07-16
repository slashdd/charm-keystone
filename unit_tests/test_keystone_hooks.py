from mock import call, patch, MagicMock
import os

from test_utils import CharmTestCase

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'keystone'
    import keystone_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import keystone_hooks as hooks
from charmhelpers.contrib import unison

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    # charmhelpers.core.hookenv
    'Hooks',
    'config',
    'is_relation_made',
    'log',
    'filter_installed_packages',
    'relation_ids',
    'relation_list',
    'relation_set',
    'relation_get',
    'related_units',
    'unit_get',
    'peer_echo',
    # charmhelpers.core.host
    'apt_install',
    'apt_update',
    'restart_on_change',
    # charmhelpers.contrib.openstack.utils
    'configure_installation_source',
    # charmhelpers.contrib.hahelpers.cluster_utils
    'is_leader',
    'eligible_leader',
    'get_hacluster_config',
    # keystone_utils
    'restart_map',
    'register_configs',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'save_script_rc',
    'migrate_database',
    'ensure_initial_admin',
    'add_service_to_keystone',
    'synchronize_ca',
    # other
    'check_call',
    'execd_preinstall',
    'mkdir',
    'os',
    'time',
    # ip
    'get_iface_for_address',
    'get_netmask_for_address',
]


class KeystoneRelationTests(CharmTestCase):

    def setUp(self):
        super(KeystoneRelationTests, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.ssh_user = 'juju_keystone'

    def test_install_hook(self):
        repo = 'cloud:precise-grizzly'
        self.test_config.set('openstack-origin', repo)
        hooks.install()
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(
            ['haproxy', 'unison', 'python-keystoneclient',
             'uuid', 'python-mysqldb', 'openssl', 'apache2',
             'pwgen', 'keystone', 'python-psycopg2'], fatal=True)
        self.assertTrue(self.execd_preinstall.called)

    def test_db_joined(self):
        self.unit_get.return_value = 'keystone.foohost.com'
        self.is_relation_made.return_value = False
        hooks.db_joined()
        self.relation_set.assert_called_with(database='keystone',
                                             username='keystone',
                                             hostname='keystone.foohost.com')
        self.unit_get.assert_called_with('private-address')

    def test_postgresql_db_joined(self):
        self.unit_get.return_value = 'keystone.foohost.com'
        self.is_relation_made.return_value = False
        hooks.pgsql_db_joined()
        self.relation_set.assert_called_with(database='keystone'),

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(
            context.exception.message,
            'Attempting to associate a mysql database when there '
            'is already associated a postgresql one')

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_db_joined()
        self.assertEqual(
            context.exception.message,
            'Attempting to associate a postgresql database when there '
            'is already associated a mysql one')

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.pgsql_db_changed()
        self.log.assert_called_with(
            'pgsql-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    def _postgresql_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['pgsql-db']
        configs.write = MagicMock()
        hooks.pgsql_db_changed()

    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    def test_db_changed(self, identity_changed, configs):
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        self._shared_db_test(configs)
        self.assertEquals([call('/etc/keystone/keystone.conf')],
                          configs.write.call_args_list)
        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    def test_postgresql_db_changed(self, identity_changed, configs):
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        self._postgresql_db_test(configs)
        self.assertEquals([call('/etc/keystone/keystone.conf')],
                          configs.write.call_args_list)
        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_openstack_upgrade_leader(
            self, configure_https, identity_changed,
            configs, get_homedir, ensure_user):
        self.openstack_upgrade_available.return_value = False
        self.eligible_leader.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.relation_list.return_value = ['unit/0']

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_openstack_upgrade_not_leader(
            self, configure_https, identity_changed,
            configs, get_homedir, ensure_user):
        self.openstack_upgrade_available.return_value = False
        self.eligible_leader.return_value = False

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertFalse(self.migrate_database.called)
        self.assertFalse(self.ensure_initial_admin.called)
        self.assertFalse(identity_changed.called)

    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_openstack_upgrade(
            self, configure_https, identity_changed,
            configs, get_homedir, ensure_user):
        self.openstack_upgrade_available.return_value = True
        self.eligible_leader.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.relation_list.return_value = ['unit/0']

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.assertTrue(self.do_openstack_upgrade.called)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    def test_identity_changed_leader(self):
        self.eligible_leader.return_value = True
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.add_service_to_keystone.assert_called_with(
            'identity-service:0',
            'unit/0')
        self.assertTrue(self.synchronize_ca.called)

    def test_identity_changed_no_leader(self):
        self.eligible_leader.return_value = False
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.assertFalse(self.add_service_to_keystone.called)
        self.log.assert_called_with(
            'Deferring identity_changed() to service leader.')

    @patch.object(unison, 'ssh_authorized_peers')
    def test_cluster_joined(self, ssh_authorized_peers):
        hooks.cluster_joined()
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='juju_keystone',
            peer_interface='cluster', ensure_local_user=True)

    @patch.object(unison, 'ssh_authorized_peers')
    @patch.object(hooks, 'CONFIGS')
    def test_cluster_changed(self, configs, ssh_authorized_peers):
        hooks.cluster_changed()
        self.peer_echo.assert_called_with(includes=['_passwd'])
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertTrue(self.synchronize_ca.called)
        self.assertTrue(configs.write_all.called)

    def test_ha_joined(self):
        self.get_hacluster_config.return_value = {
            'vip': '10.10.10.10',
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080'
        }
        self.get_iface_for_address.return_value = 'em1'
        self.get_netmask_for_address.return_value = '255.255.255.0'
        hooks.ha_joined()
        args = {
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_ks_haproxy': 'haproxy'},
            'resources': {'res_ks_em1_vip': 'ocf:heartbeat:IPaddr2',
                          'res_ks_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_ks_em1_vip': 'params ip="10.10.10.10"'
                                  ' cidr_netmask="255.255.255.0" nic="em1"',
                'res_ks_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_ks_haproxy': 'res_ks_haproxy'}
        }
        self.relation_set.assert_called_with(**args)

    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_not_clustered_not_leader(self, configs):
        self.relation_get.return_value = False
        self.is_leader.return_value = False

        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)

    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_clustered_leader(self, configs):
        self.relation_get.return_value = True
        self.is_leader.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.test_config.set('vip', '10.10.10.10')

        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)
        self.log.assert_called_with(
            'Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        self.relation_set.assert_called_with(relation_id='identity-service:0',
                                             auth_host='10.10.10.10',
                                             service_host='10.10.10.10')

    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_enable(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['https']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2ensite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_disable(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2dissite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch.object(unison, 'ssh_authorized_peers')
    def test_upgrade_charm_leader(self, ssh_authorized_peers):
        self.eligible_leader.return_value = True
        self.filter_installed_packages.return_value = []
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertTrue(self.synchronize_ca.called)
        self.log.assert_called_with(
            'Cluster leader - ensuring endpoint configuration'
            ' is up to date')
        self.assertTrue(self.ensure_initial_admin.called)

    @patch.object(unison, 'ssh_authorized_peers')
    def test_upgrade_charm_not_leader(self, ssh_authorized_peers):
        self.eligible_leader.return_value = False
        self.filter_installed_packages.return_value = []
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertTrue(self.synchronize_ca.called)
        self.assertFalse(self.log.called)
        self.assertFalse(self.ensure_initial_admin.called)
