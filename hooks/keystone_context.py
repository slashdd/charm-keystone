from charmhelpers.core.hookenv import (
    config, unit_private_ip)

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
    is_clustered,
)

from charmhelpers.contrib.network.ip import(
    get_ipv6_addr,
)

from subprocess import (
    check_call
)

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

    def configure_cert(self):
        # import keystone_ssl as ssl
        from keystone_utils import SSH_USER, get_ca
        if not os.path.isdir('/etc/apache2/ssl'):
            os.mkdir('/etc/apache2/ssl')
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.service_namespace)
        if not os.path.isdir(ssl_dir):
            os.mkdir(ssl_dir)
        if is_clustered():
            https_cn = config('vip')
        else:
            https_cn = unit_private_ip()
        ca = get_ca(user=SSH_USER)
        cert, key = ca.get_cert_and_key(common_name=https_cn)
        with open(os.path.join(ssl_dir, 'cert'), 'w') as cert_out:
            cert_out.write(cert)
        with open(os.path.join(ssl_dir, 'key'), 'w') as key_out:
            key_out.write(key)
        if ca:
            with open(CA_CERT_PATH, 'w') as ca_out:
                ca_out.write(ca.get_ca_bundle())
            check_call(['update-ca-certificates'])


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

        if config('prefer-ipv6'):
            ctxt['local_host'] = 'ip6-localhost'
            ctxt['haproxy_host'] = '::'
            ctxt['stat_port'] = ':::8888'
        else:
            ctxt['local_host'] = '127.0.0.1'
            ctxt['haproxy_host'] = '0.0.0.0'
            ctxt['stat_port'] = ':8888'
        return ctxt


class KeystoneContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        from keystone_utils import api_port, set_admin_token
        ctxt = {}
        ctxt['token'] = set_admin_token(config('admin-token'))
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'))
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'))
        ctxt['debug'] = config('debug') in ['yes', 'true', 'True']
        ctxt['verbose'] = config('verbose') in ['yes', 'true', 'True']
        if config('enable-pki') not in ['false', 'False', 'no', 'No']:
            ctxt['signing'] = True
        return ctxt


class KeystoneIPv6Context(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}
        if config('prefer-ipv6'):
                host = get_ipv6_addr()
                ctxt['bind_host'] = host
	else:
 	    ctxt['bind_host'] = '0.0.0.0'
        return ctxt
