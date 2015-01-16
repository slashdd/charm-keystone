#!/usr/bin/python

import hashlib
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
    local_unit,
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
    sync_db_with_multi_ipv6_addresses
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
    services,
    CLUSTER_RES,
    KEYSTONE_CONF,
    SSH_USER,
    STORED_PASSWD,
    setup_ipv6,
    send_notifications,
)

from charmhelpers.contrib.hahelpers.cluster import (
    eligible_leader,
    is_leader,
    get_hacluster_config,
)

from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.peerstorage import (
    peer_retrieve_by_prefix,
    peer_echo,
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    get_address_in_network,
    get_ipv6_addr,
    is_ipv6
)
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport import nrpe

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
    if config('prefer-ipv6'):
        setup_ipv6()
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))

    unison.ensure_user(user=SSH_USER, group='keystone')
    homedir = unison.get_homedir(SSH_USER)
    if not os.path.isdir(homedir):
        mkdir(homedir, SSH_USER, 'keystone', 0o775)

    if openstack_upgrade_available('keystone'):
        do_openstack_upgrade(configs=CONFIGS)

    check_call(['chmod', '-R', 'g+wrx', '/var/lib/keystone/'])

    save_script_rc()
    configure_https()
    update_nrpe_config()
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

    [cluster_joined(rid) for rid in relation_ids('cluster')]


@hooks.hook('shared-db-relation-joined')
def db_joined():
    if is_relation_made('pgsql-db'):
        # error, postgresql is used
        e = ('Attempting to associate a mysql database when there is already '
             'associated a postgresql one')
        log(e, level=ERROR)
        raise Exception(e)

    if config('prefer-ipv6'):
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))
    else:
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
            # Bugs 1353135 & 1187508. Dbs can appear to be ready before the
            # units acl entry has been added. So, if the db supports passing
            # a list of permitted units then check if we're in the list.
            allowed_units = relation_get('allowed_units')
            print "allowed_units:" + str(allowed_units)
            if allowed_units and local_unit() not in allowed_units.split():
                log('Allowed_units list provided and this unit not present')
                return
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


@hooks.hook('identity-service-relation-changed')
def identity_changed(relation_id=None, remote_unit=None):
    notifications = {}
    if eligible_leader(CLUSTER_RES):
        add_service_to_keystone(relation_id, remote_unit)
        synchronize_ca()

        settings = relation_get(rid=relation_id, unit=remote_unit)
        service = settings.get('service', None)
        if service:
            # If service is known and endpoint has changed, notify service if
            # it is related with notifications interface.
            csum = hashlib.sha256()
            # We base the decision to notify on whether these parameters have
            # changed (if csum is unchanged from previous notify, relation will
            # not fire).
            csum.update(settings.get('public_url', None))
            csum.update(settings.get('admin_url', None))
            csum.update(settings.get('internal_url', None))
            notifications['%s-endpoint-changed' % (service)] = csum.hexdigest()
    else:
        # Each unit needs to set the db information otherwise if the unit
        # with the info dies the settings die with it Bug# 1355848
        for rel_id in relation_ids('identity-service'):
            peerdb_settings = peer_retrieve_by_prefix(rel_id)
            if 'service_password' in peerdb_settings:
                relation_set(relation_id=rel_id, **peerdb_settings)
        log('Deferring identity_changed() to service leader.')

    if notifications:
        send_notifications(notifications)


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='juju_keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    for addr_type in ADDRESS_TYPES:
        address = get_address_in_network(
            config('os-{}-network'.format(addr_type))
        )
        if address:
            relation_set(
                relation_id=relation_id,
                relation_settings={'{}-address'.format(addr_type): address}
            )

    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_set(relation_id=relation_id,
                     relation_settings={'private-address': private_addr})


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    # NOTE(jamespage) re-echo passwords for peer storage
    peer_echo(includes=['_passwd', 'identity-service:'])
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    synchronize_ca()
    CONFIGS.write_all()
    for r_id in relation_ids('identity-service'):
        for unit in relation_list(r_id):
            identity_changed(relation_id=r_id,
                             remote_unit=unit)


@hooks.hook('ha-relation-joined')
def ha_joined():
    cluster_config = get_hacluster_config()
    resources = {
        'res_ks_haproxy': 'lsb:haproxy',
    }
    resource_params = {
        'res_ks_haproxy': 'op monitor interval="5s"'
    }

    vip_group = []
    for vip in cluster_config['vip'].split():
        if is_ipv6(vip):
            res_ks_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_ks_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = (get_iface_for_address(vip) or
                 config('vip_iface'))
        netmask = (get_netmask_for_address(vip) or
                   config('vip_cidr'))

        if iface is not None:
            vip_key = 'res_ks_{}_vip'.format(iface)
            resources[vip_key] = res_ks_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=netmask)
            )
            vip_group.append(vip_key)

    if len(vip_group) >= 1:
        relation_set(groups={'grp_ks_vips': ' '.join(vip_group)})

    init_services = {
        'res_ks_haproxy': 'haproxy'
    }
    clones = {
        'cl_ks_haproxy': 'res_ks_haproxy'
    }
    relation_set(init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
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
        for unit in related_units(rid):
            identity_changed(relation_id=rid, remote_unit=unit)


@hooks.hook('identity-admin-relation-changed')
def admin_relation_changed():
    # TODO: fixup
    relation_data = {
        'service_hostname': unit_get('private-address'),
        'service_port': config('service-port'),
        'service_username': config('admin-user'),
        'service_tenant_name': config('admin-role'),
        'service_region': config('region'),
    }
    if os.path.isfile(STORED_PASSWD):
        with open(STORED_PASSWD) as f:
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
    update_nrpe_config()
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


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe_setup.write()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
