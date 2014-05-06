#!/usr/bin/python

import os
import sys
import time

from subprocess import check_call

from charmhelpers.contrib import unison

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    is_relation_made,
    log,
    ERROR,
    relation_get,
    relation_ids,
    relation_set,
    related_units,
    unit_get,
)

from charmhelpers.core.host import (
    mkdir,
    restart_on_change,
)

from charmhelpers.fetch import (
    apt_install, apt_update,
    filter_installed_packages
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available,
)

from keystone_utils import (
    add_service_to_keystone,
    determine_packages,
    do_openstack_upgrade,
    ensure_initial_admin,
    migrate_database,
    save_script_rc,
    synchronize_ca,
    register_configs,
    relation_list,
    restart_map,
    CLUSTER_RES,
    KEYSTONE_CONF,
    SSH_USER,
    stored_passwd,
)

from charmhelpers.contrib.hahelpers.cluster import (
    eligible_leader,
    get_hacluster_config,
    is_leader,
)

from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.peerstorage import peer_echo

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))
    apt_update()
    apt_install(determine_packages(), fatal=True)


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    unison.ensure_user(user=SSH_USER, group='keystone')
    homedir = unison.get_homedir(SSH_USER)
    if not os.path.isdir(homedir):
        mkdir(homedir, SSH_USER, 'keystone', 0o775)

    if openstack_upgrade_available('keystone'):
        do_openstack_upgrade(configs=CONFIGS)

    check_call(['chmod', '-R', 'g+wrx', '/var/lib/keystone/'])

    save_script_rc()
    configure_https()
    CONFIGS.write_all()
    if eligible_leader(CLUSTER_RES):
        migrate_database()
        ensure_initial_admin(config)
        log('Firing identity_changed hook for all related services.')
        # HTTPS may have been set - so fire all identity relations
        # again
        for r_id in relation_ids('identity-service'):
            for unit in relation_list(r_id):
                identity_changed(relation_id=r_id,
                                 remote_unit=unit)


@hooks.hook('shared-db-relation-joined')
def db_joined():
    if is_relation_made('pgsql-db'):
        # error, postgresql is used
        e = ('Attempting to associate a mysql database when there is already '
             'associated a postgresql one')
        log(e, level=ERROR)
        raise Exception(e)

    relation_set(database=config('database'),
                 username=config('database-user'),
                 hostname=unit_get('private-address'))


@hooks.hook('pgsql-db-relation-joined')
def pgsql_db_joined():
    if is_relation_made('shared-db'):
        # raise error
        e = ('Attempting to associate a postgresql database when there'
             ' is already associated a mysql one')
        log(e, level=ERROR)
        raise Exception(e)

    relation_set(database=config('database'))


@hooks.hook('shared-db-relation-changed')
@restart_on_change(restart_map())
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
    else:
        CONFIGS.write(KEYSTONE_CONF)
        if eligible_leader(CLUSTER_RES):
            migrate_database()
            ensure_initial_admin(config)
            # Ensure any existing service entries are updated in the
            # new database backend
            for rid in relation_ids('identity-service'):
                for unit in related_units(rid):
                    identity_changed(relation_id=rid, remote_unit=unit)


@hooks.hook('pgsql-db-relation-changed')
@restart_on_change(restart_map())
def pgsql_db_changed():
    if 'pgsql-db' not in CONFIGS.complete_contexts():
        log('pgsql-db relation incomplete. Peer not ready?')
    else:
        CONFIGS.write(KEYSTONE_CONF)
        if eligible_leader(CLUSTER_RES):
            migrate_database()
            ensure_initial_admin(config)
            # Ensure any existing service entries are updated in the
            # new database backend
            for rid in relation_ids('identity-service'):
                for unit in related_units(rid):
                    identity_changed(relation_id=rid, remote_unit=unit)


@hooks.hook('identity-service-relation-joined')
def identity_joined():
    """ Do nothing until we get information about requested service """
    pass


@hooks.hook('identity-service-relation-changed')
def identity_changed(relation_id=None, remote_unit=None):
    if eligible_leader(CLUSTER_RES):
        add_service_to_keystone(relation_id, remote_unit)
        synchronize_ca()
    else:
        log('Deferring identity_changed() to service leader.')


@hooks.hook('cluster-relation-joined')
def cluster_joined():
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='juju_keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    # NOTE(jamespage) re-echo passwords for peer storage
    peer_echo(includes=['_passwd'])
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    synchronize_ca()
    CONFIGS.write_all()


@hooks.hook('ha-relation-joined')
def ha_joined():
    config = get_hacluster_config()
    resources = {
        'res_ks_vip': 'ocf:heartbeat:IPaddr2',
        'res_ks_haproxy': 'lsb:haproxy',
    }
    vip_params = 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                 (config['vip'], config['vip_cidr'], config['vip_iface'])
    resource_params = {
        'res_ks_vip': vip_params,
        'res_ks_haproxy': 'op monitor interval="5s"'
    }
    init_services = {
        'res_ks_haproxy': 'haproxy'
    }
    clones = {
        'cl_ks_haproxy': 'res_ks_haproxy'
    }
    relation_set(init_services=init_services,
                 corosync_bindiface=config['ha-bindiface'],
                 corosync_mcastport=config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('ha-relation-changed')
@restart_on_change(restart_map())
def ha_changed():
    clustered = relation_get('clustered')
    CONFIGS.write_all()
    if (clustered is not None and
            is_leader(CLUSTER_RES)):
        ensure_initial_admin(config)
        log('Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        for rid in relation_ids('identity-service'):
            relation_set(relation_id=rid,
                         auth_host=config('vip'),
                         service_host=config('vip'))


@hooks.hook('identity-admin-relation-joined')
def admin_relation_joined():
    """ Do nothing until we get information about requested service """
    pass


@hooks.hook('identity-admin-relation-changed')
def admin_relation_changed():
    relation_data = {
        'service_hostname': config('hostname'),
        'service_port': config('service-port'),
        'service_username': config('admin-user'),
        'service_tenant_name': config('admin-role'),
        'service_region': config('region'),
    }
    if os.path.isfile(stored_passwd):
        with open(stored_passwd) as f:
            relation_data['service_password'] = f.readline().strip('\n')
    relation_set(**relation_data)


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        check_call(cmd)


@hooks.hook('upgrade-charm')
@restart_on_change(restart_map(), stopstart=True)
def upgrade_charm():
    apt_install(filter_installed_packages(determine_packages()))
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    synchronize_ca()
    if eligible_leader(CLUSTER_RES):
        log('Cluster leader - ensuring endpoint configuration'
            ' is up to date')
        time.sleep(10)
        ensure_initial_admin(config)
        # Deal with interface changes for icehouse
        for r_id in relation_ids('identity-service'):
            for unit in relation_list(r_id):
                identity_changed(relation_id=r_id,
                                 remote_unit=unit)
    CONFIGS.write_all()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
