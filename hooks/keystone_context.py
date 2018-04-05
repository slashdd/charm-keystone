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

import hashlib
import os

from base64 import b64decode

from charmhelpers.core.host import (
    mkdir,
    write_file,
    service_restart,
)

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    DC_RESOURCE_NAME,
    determine_apache_port,
    determine_api_port,
    is_elected_leader,
    https,
)

from charmhelpers.core.hookenv import (
    config,
    log,
    leader_get,
    DEBUG,
    INFO,
)

from charmhelpers.core.strutils import (
    bool_from_string,
)

from charmhelpers.contrib.hahelpers.apache import install_ca_cert

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'


def is_cert_provided_in_config():
    cert = config('ssl_cert')
    key = config('ssl_key')
    return bool(cert and key)


class SSLContext(context.ApacheSSLContext):

    def configure_cert(self, cn):
        from keystone_utils import (
            SSH_USER,
            get_ca,
            ensure_permissions,
            is_ssl_cert_master,
            KEYSTONE_USER,
        )

        # Ensure ssl dir exists whether master or not
        perms = 0o775
        mkdir(path=self.ssl_dir, owner=SSH_USER, group=KEYSTONE_USER,
              perms=perms)
        # Ensure accessible by keystone ssh user and group (for sync)
        ensure_permissions(self.ssl_dir, user=SSH_USER, group=KEYSTONE_USER,
                           perms=perms)

        if not is_cert_provided_in_config() and not is_ssl_cert_master():
            log("Not ssl-cert-master - skipping apache cert config until "
                "master is elected", level=INFO)
            return

        log("Creating apache ssl certs in %s" % (self.ssl_dir), level=INFO)

        cert = config('ssl_cert')
        key = config('ssl_key')

        if not (cert and key):
            ca = get_ca(user=SSH_USER)
            cert, key = ca.get_cert_and_key(common_name=cn)
        else:
            cert = b64decode(cert)
            key = b64decode(key)

        write_file(path=os.path.join(self.ssl_dir, 'cert_{}'.format(cn)),
                   content=cert, owner=SSH_USER, group=KEYSTONE_USER,
                   perms=0o640)
        write_file(path=os.path.join(self.ssl_dir, 'key_{}'.format(cn)),
                   content=key, owner=SSH_USER, group=KEYSTONE_USER,
                   perms=0o640)

    def configure_ca(self):
        from keystone_utils import (
            SSH_USER,
            get_ca,
            ensure_permissions,
            is_ssl_cert_master,
            KEYSTONE_USER,
        )

        if not is_cert_provided_in_config() and not is_ssl_cert_master():
            log("Not ssl-cert-master - skipping apache ca config until "
                "master is elected", level=INFO)
            return

        cert = config('ssl_cert')
        key = config('ssl_key')

        ca_cert = config('ssl_ca')
        if ca_cert:
            ca_cert = b64decode(ca_cert)
        elif not (cert and key):
            # NOTE(hopem): if a cert and key are provided as config we don't
            # mandate that a CA is also provided since it isn't necessarily
            # needed. As a result we only generate a custom CA if we are also
            # generating cert and key.
            ca = get_ca(user=SSH_USER)
            ca_cert = ca.get_ca_bundle()

        if ca_cert:
            # Ensure accessible by keystone ssh user and group (unison)
            install_ca_cert(ca_cert)
            ensure_permissions(CA_CERT_PATH, user=SSH_USER,
                               group=KEYSTONE_USER, perms=0o0644)

    def canonical_names(self):
        addresses = self.get_network_addresses()
        addrs = []
        for address, endpoint in addresses:
            addrs.append(endpoint)

        return list(set(addrs))


class ApacheSSLContext(SSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = os.path.join('/etc/apache2/ssl/', service_namespace)

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
            update_hash_from_path,
        )

        ssl_paths = [CA_CERT_PATH, self.ssl_dir]

        self.external_ports = determine_ports()
        before = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(before, path)

        ret = super(ApacheSSLContext, self).__call__()

        after = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(after, path)

        # Ensure that apache2 is restarted if these change
        if before.hexdigest() != after.hexdigest():
            service_restart('apache2')

        return ret


class NginxSSLContext(SSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = ('/var/snap/{}/common/lib/juju_ssl/{}/'
               ''.format(service_namespace, service_namespace))

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
            update_hash_from_path,
            APACHE_SSL_DIR
        )

        ssl_paths = [CA_CERT_PATH, APACHE_SSL_DIR]

        self.external_ports = determine_ports()
        before = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(before, path)

        ret = super(NginxSSLContext, self).__call__()
        if not ret:
            log("SSL not used", level='DEBUG')
            return {}

        after = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(after, path)

        # Ensure that Nginx is restarted if these change
        if before.hexdigest() != after.hexdigest():
            service_restart('snap.keystone.nginx')

        # Transform for use by Nginx
        """
        {'endpoints': [(u'10.5.0.30', u'10.5.0.30', 4990, 4980),
                       (u'10.5.0.30', u'10.5.0.30', 35347, 35337)],
         'ext_ports': [4990, 35347],
         'namespace': 'keystone'}
        """

        nginx_ret = {}
        nginx_ret['ssl'] = https()
        nginx_ret['namespace'] = self.service_namespace
        endpoints = {}
        for ep in ret['endpoints']:
            int_address, address, ext, internal = ep
            if ext <= 5000:
                endpoints['public'] = {
                    'socket': 'public',
                    'address': address,
                    'ext': ext}
            elif ext >= 35337:
                endpoints['admin'] = {
                    'socket': 'admin',
                    'address': address,
                    'ext': ext}
            else:
                log("Unrecognized internal port", level='ERROR')
        nginx_ret['endpoints'] = endpoints

        return nginx_ret

    def enable_modules(self):
        return


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
        a_admin_port = determine_apache_port(api_port('keystone-admin'),
                                             singlenode_mode=True)
        a_public_port = determine_apache_port(api_port('keystone-public'),
                                              singlenode_mode=True)

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
            api_port, set_admin_token, endpoint_url, resolve_address,
            PUBLIC, ADMIN, PKI_CERTS_DIR, ensure_pki_cert_paths, ADMIN_DOMAIN,
            snap_install_requested, get_api_version,
        )
        ctxt = {}
        ctxt['token'] = set_admin_token(config('admin-token'))
        ctxt['api_version'] = get_api_version()
        ctxt['admin_role'] = config('admin-role')
        if ctxt['api_version'] > 2:
            ctxt['service_tenant_id'] = \
                leader_get(attribute='service_tenant_id')
            ctxt['admin_domain_name'] = ADMIN_DOMAIN
            ctxt['admin_domain_id'] = \
                leader_get(attribute='admin_domain_id')
            ctxt['default_domain_id'] = \
                leader_get(attribute='default_domain_id')
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'),
                                                singlenode_mode=True)
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'),
                                                 singlenode_mode=True)

        ctxt['debug'] = config('debug')
        ctxt['verbose'] = config('verbose')
        ctxt['token_expiration'] = config('token-expiration')

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

        enable_pki = config('enable-pki')
        if enable_pki and bool_from_string(enable_pki):
            log("Enabling PKI", level=DEBUG)
            ctxt['token_provider'] = 'pki'

            # NOTE(jamespage): Only check PKI configuration if the PKI
            #                  token format is in use, which has been
            #                  removed as of OpenStack Ocata.
            ensure_pki_cert_paths()
            certs = os.path.join(PKI_CERTS_DIR, 'certs')
            privates = os.path.join(PKI_CERTS_DIR, 'privates')
            ctxt['enable_signing'] = True
            ctxt.update({'certfile': os.path.join(certs, 'signing_cert.pem'),
                         'keyfile': os.path.join(privates, 'signing_key.pem'),
                         'ca_certs': os.path.join(certs, 'ca.pem'),
                         'ca_key': os.path.join(certs, 'ca_key.pem')})
        else:
            ctxt['enable_signing'] = False

        # Base endpoint URL's which are used in keystone responses
        # to unauthenticated requests to redirect clients to the
        # correct auth URL.
        ctxt['public_endpoint'] = endpoint_url(
            resolve_address(PUBLIC),
            api_port('keystone-public')).replace('v2.0', '')
        ctxt['admin_endpoint'] = endpoint_url(
            resolve_address(ADMIN),
            api_port('keystone-admin')).replace('v2.0', '')

        if snap_install_requested():
            ctxt['domain_config_dir'] = (
                '/var/snap/keystone/common/etc/keystone/domains')
            ctxt['log_config'] = (
                '/var/snap/keystone/common/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = (
                '/var/snap/keystone/common/etc/keystone/keystone-paste.ini')
        else:
            ctxt['domain_config_dir'] = '/etc/keystone/domains'
            ctxt['log_config'] = ('/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = '/etc/keystone/keystone-paste.ini'

        return ctxt


class KeystoneLoggingContext(context.OSContextGenerator):

    def __call__(self):
        from keystone_utils import (
            snap_install_requested,
        )
        ctxt = {}
        debug = config('debug')
        if debug:
            ctxt['root_level'] = 'DEBUG'
        log_level = config('log-level')
        log_level_accepted_params = ['WARNING', 'INFO', 'DEBUG', 'ERROR']
        if log_level in log_level_accepted_params:
            ctxt['log_level'] = config('log-level')
        else:
            log("log-level must be one of the following states "
                "(WARNING, INFO, DEBUG, ERROR) keeping the current state.")
            ctxt['log_level'] = None
        if snap_install_requested():
            ctxt['log_file'] = (
                '/var/snap/keystone/common/log/keystone.log')
        else:
            ctxt['log_file'] = '/var/log/keystone/keystone.log'

        return ctxt


class TokenFlushContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {
            'token_flush': is_elected_leader(DC_RESOURCE_NAME)
        }
        return ctxt
