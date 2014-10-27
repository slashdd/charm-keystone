from charmhelpers.core.hookenv import config, unit_get, log

from charmhelpers.core.host import mkdir, write_file

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
    is_clustered
)

from charmhelpers.contrib.hahelpers.apache import install_ca_cert

from charmhelpers.contrib.network.ip import (
    get_address_in_network, is_address_in_network)

import os

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'


class ApacheSSLContext(context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import determine_ports
        self.external_ports = determine_ports()
        return super(ApacheSSLContext, self).__call__()

    def configure_cert(self, cn):
        from keystone_utils import SSH_USER, get_ca
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.service_namespace)
        mkdir(path=ssl_dir)
        ca = get_ca(user=SSH_USER)
        cert, key = ca.get_cert_and_key(common_name=cn)
        write_file(path=os.path.join(ssl_dir, 'cert_{}'.format(cn)),
                   content=cert)
        write_file(path=os.path.join(ssl_dir, 'key_{}'.format(cn)),
                   content=key)

    def configure_ca(self):
        from keystone_utils import SSH_USER, get_ca
        ca = get_ca(user=SSH_USER)
        install_ca_cert(ca.get_ca_bundle())

    def canonical_names(self):
        addresses = []
        vips = []
        if config('vip'):
            vips = config('vip').split()
        for network_type in ['os-internal-network',
                             'os-admin-network',
                             'os-public-network']:
            address = get_address_in_network(config(network_type),
                                             unit_get('private-address'))
            if len(vips) > 1 and is_clustered():
                if not config(network_type):
                    log("Multinet is used, but network_type (%s) is None."
                        % network_type, level='WARNING')
                    continue
                for vip in vips:
                    if is_address_in_network(config(network_type), vip):
                        addresses.append(vip)
                        break
            elif is_clustered():
                addresses.append(config('vip'))
            else:
                addresses.append(address)
        return list(set(addresses))


class HAProxyContext(context.HAProxyContext):
    interfaces = []

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        from keystone_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        listen_ports = {}
        listen_ports['admin_port'] = api_port('keystone-admin')
        listen_ports['public_port'] = api_port('keystone-public')

        # Apache ports
        a_admin_port = determine_apache_port(api_port('keystone-admin'))
        a_public_port = determine_apache_port(api_port('keystone-public'))

        port_mapping = {
            'admin-port': [
                api_port('keystone-admin'), a_admin_port],
            'public-port': [
                api_port('keystone-public'), a_public_port],
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for keystone.conf
        ctxt['listen_ports'] = listen_ports
        return ctxt


class KeystoneContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        from keystone_utils import (
            api_port, set_admin_token,
            endpoint_url, resolve_address,
            PUBLIC, ADMIN
        )
        ctxt = {}
        ctxt['token'] = set_admin_token(config('admin-token'))
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'))
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'))
        ctxt['debug'] = config('debug') in ['yes', 'true', 'True']
        ctxt['verbose'] = config('verbose') in ['yes', 'true', 'True']
        ctxt['identity_backend'] = config('identity-backend')
        ctxt['assignment_backend'] = config('assignment-backend')
        if config('identity-backend') == 'ldap':
            ctxt['ldap_server'] = config('ldap-server')
            ctxt['ldap_user'] = config('ldap-user')
            ctxt['ldap_password'] = config('ldap-password')
            ctxt['ldap_suffix'] = config('ldap-suffix')
            ctxt['ldap_readonly'] = config('ldap-readonly')
            ldap_flags = config('ldap-config-flags')
            if ldap_flags:
                flags = context.config_flags_parser(ldap_flags)
                ctxt['ldap_config_flags'] = flags

        if config('enable-pki') not in ['false', 'False', 'no', 'No']:
            ctxt['signing'] = True

        # Base endpoint URL's which are used in keystone responses
        # to unauthenticated requests to redirect clients to the
        # correct auth URL.
        ctxt['public_endpoint'] = endpoint_url(
            resolve_address(PUBLIC),
            api_port('keystone-public')).rstrip('v2.0')
        ctxt['admin_endpoint'] = endpoint_url(
            resolve_address(ADMIN),
            api_port('keystone-admin')).rstrip('v2.0')
        return ctxt
