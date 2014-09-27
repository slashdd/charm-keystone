#!/usr/bin/python

import amulet

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG, # flake8: noqa
    ERROR
)

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(ERROR)


class KeystoneBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic keystone deployment."""

    def __init__(self, series=None, openstack=None, source=None, stable=False):
        """Deploy the entire test environment."""
        super(KeystoneBasicDeployment, self).__init__(series, openstack, source, stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where keystone is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'keystone'}
        other_services = [{'name': 'mysql'}, {'name': 'cinder'}]
        super(KeystoneBasicDeployment, self)._add_services(this_service,
                                                           other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {'keystone:shared-db': 'mysql:shared-db',
                     'cinder:identity-service': 'keystone:identity-service'}
        super(KeystoneBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        mysql_config = {'dataset-size': '50%'}
        cinder_config = {'block-device': 'None'}
        configs = {'keystone': keystone_config,
                   'mysql': mysql_config,
                   'cinder': cinder_config}
        super(KeystoneBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.cinder_sentry = self.d.sentry.unit['cinder/0']

        self._authenticate_keystone_admin()

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)
            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user, password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

    def _authenticate_keystone_admin(self):
        """Authenticate admin with keystone

           Note: A side-effect of test_restart_on_config_change() is that it
           restarts keystone services, so all tests that use self.keystone
           will require re-authentication.
           """
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

    def _authenticate_keystone_demo(self):
        """Authenticate demo user with keystone

           Note: A side-effect of test_restart_on_config_change() is that it
           restarts keystone services, so all tests that use
           self.keystone_demo will require re-authentication.
           """
        self._authenticate_keystone_admin()
        self.keystone_demo = u.authenticate_keystone_user(self.keystone,
                                                        user=self.demo_user,
                                                        password='password',
                                                        tenant=self.demo_tenant)

    def test_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        commands = {
            self.mysql_sentry: ['status mysql'],
            self.keystone_sentry: ['status keystone'],
            self.cinder_sentry: ['status cinder-api', 'status cinder-scheduler',
                                 'status cinder-volume']
        }
        ret = u.validate_services(commands)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_tenants(self):
        """Verify all existing tenants."""
        tenant1 = {'enabled': True,
                   'description': 'Created by Juju',
                   'name': 'services',
                   'id': u.not_null}
        tenant2 = {'enabled': True,
                   'description': 'demo tenant',
                   'name': 'demoTenant',
                   'id': u.not_null}
        tenant3 = {'enabled': True,
                   'description': 'Created by Juju',
                   'name': 'admin',
                   'id': u.not_null}
        expected = [tenant1, tenant2, tenant3]
        self._authenticate_keystone_admin()
        actual = self.keystone.tenants.list()

        ret = u.validate_tenant_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_roles(self):
        """Verify all existing roles."""
        role1 = {'name': 'demoRole', 'id': u.not_null}
        role2 = {'name': 'Admin', 'id': u.not_null}
        expected = [role1, role2]
        self._authenticate_keystone_admin()
        actual = self.keystone.roles.list()

        ret = u.validate_role_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_users(self):
        """Verify all existing roles."""
        user1 = {'name': 'demoUser',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': 'demo@demo.com'}
        user2 = {'name': 'admin',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': 'juju@localhost'}
        user3 = {'name': 'cinder',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': u'juju@localhost'}
        expected = [user1, user2, user3]
        self._authenticate_keystone_admin()
        actual = self.keystone.users.list()

        ret = u.validate_user_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}
        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}
        if self._get_openstack_release() > self.precise_essex:
            endpoint_vol['id'] = u.not_null
            endpoint_id['id'] = u.not_null
        expected = {'volume': [endpoint_vol], 'identity': [endpoint_id]}
        self._authenticate_keystone_demo()
        actual = self.keystone_demo.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_keystone_endpoint(self):
        """Verify the keystone endpoint data."""
        self._authenticate_keystone_admin()
        endpoints = self.keystone.endpoints.list()
        admin_port = '35357'
        internal_port = public_port = '5000'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}
        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            amulet.raise_status(amulet.FAIL,
                                msg='keystone endpoint: {}'.format(ret))

    def test_cinder_endpoint(self):
        """Verify the cinder endpoint data."""
        self._authenticate_keystone_admin()
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8776'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}
        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            amulet.raise_status(amulet.FAIL,
                                msg='cinder endpoint: {}'.format(ret))

    def test_keystone_shared_db_relation(self):
        """Verify the keystone shared-db relation data"""
        unit = self.keystone_sentry
        relation = ['shared-db', 'mysql:shared-db']
        expected = {
            'username': 'keystone',
            'private-address': u.valid_ip,
            'hostname': u.valid_ip,
            'database': 'keystone'
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_mysql_shared_db_relation(self):
        """Verify the mysql shared-db relation data"""
        unit = self.mysql_sentry
        relation = ['shared-db', 'keystone:shared-db']
        expected_data = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'db_host': u.valid_ip
        }
        ret = u.validate_relation_data(unit, relation, expected_data)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_keystone_identity_service_relation(self):
        """Verify the keystone identity-service relation data"""
        unit = self.keystone_sentry
        relation = ['identity-service', 'cinder:identity-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'admin_token': 'ubuntutesting',
            'service_password': u.not_null,
            'service_port': '5000',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'https_keystone': 'False',
            'auth_host': u.valid_ip,
            'service_username': 'cinder',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('cinder identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_cinder_identity_service_relation(self):
        """Verify the cinder identity-service relation data"""
        unit = self.cinder_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'service': 'cinder',
            'region': 'RegionOne',
            'public_url': u.valid_url,
            'internal_url': u.valid_url,
            'private-address': u.valid_ip,
            'admin_url': u.valid_url
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('cinder identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_restart_on_config_change(self):
        """Verify that keystone is restarted when the config is changed."""
        self.d.configure('keystone', {'verbose': 'True'})
        if not u.service_restarted(self.keystone_sentry, 'keystone-all',
                                  '/etc/keystone/keystone.conf',
                                  sleep_time=30):
            self.d.configure('keystone', {'verbose': 'False'})
            message = "keystone service didn't restart after config change"
            amulet.raise_status(amulet.FAIL, msg=message)
        self.d.configure('keystone', {'verbose': 'False'})

    def test_default_config(self):
        """Verify the data in the keystone config file's default section,
           comparing some of the variables vs relation data."""
        unit = self.keystone_sentry
        conf = '/etc/keystone/keystone.conf'
        relation = unit.relation('identity-service', 'cinder:identity-service')
        expected = {'admin_token': relation['admin_token'],
                    'admin_port': relation['auth_port'],
                    'public_port': relation['service_port'],
                    'use_syslog': 'False',
                    'log_config': '/etc/keystone/logging.conf',
                    'debug': 'False',
                    'verbose': 'False'}

        ret = u.validate_config_data(unit, conf, 'DEFAULT', expected)
        if ret:
            message = "keystone config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_database_config(self):
        """Verify the data in the keystone config file's database (or sql
           depending on release) section, comparing vs relation data."""
        unit = self.keystone_sentry
        conf = '/etc/keystone/keystone.conf'
        relation = self.mysql_sentry.relation('shared-db', 'keystone:shared-db')
        db_uri = "mysql://{}:{}@{}/{}".format('keystone', relation['password'],
                                              relation['db_host'], 'keystone')
        expected = {'connection': db_uri, 'idle_timeout': '200'}

        if self._get_openstack_release() > self.precise_havana:
            ret = u.validate_config_data(unit, conf, 'database', expected)
        else:
            ret = u.validate_config_data(unit, conf, 'sql', expected)
        if ret:
            message = "keystone config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)
