# Overview

The keystone charm deploys [Keystone][upstream-keystone], the core OpenStack
service that provides API client authentication, service discovery, and
distributed multi-tenant authorization. The charm works alongside other
Juju-deployed OpenStack services.

# Usage

## Configuration

This section covers common and/or important configuration options. See file
`config.yaml` for the full list of options, along with their descriptions and
default values. See the [Juju documentation][juju-docs-config-apps] for details
on configuring applications.

#### `openstack-origin`

The `openstack-origin` option states the software sources. A common value is an
OpenStack UCA release (e.g. 'cloud:bionic-ussuri' or 'cloud:focal-victoria').
See [Ubuntu Cloud Archive][wiki-uca]. The underlying host's existing apt
sources will be used if this option is not specified (this behaviour can be
explicitly chosen by using the value of 'distro').

## Deployment

Keystone is often containerised. Here a single unit is deployed to a new
container on machine '1':

    juju deploy --to lxd:1 keystone

Now connect the keystone application to an existing cloud database. The
database application is determined by the series. Prior to focal
[percona-cluster][percona-cluster-charm] is used, otherwise it is
[mysql-innodb-cluster][mysql-innodb-cluster-charm]. In the example deployment
below mysql-innodb-cluster has been chosen.

    juju deploy mysql-router keystone-mysql-router
    juju add-relation keystone-mysql-router:db-router mysql-innodb-cluster:db-router
    juju add-relation keystone-mysql-router:shared-db keystone:shared-db

## Credentials

The `keystone:shared-db` relation added at deployment time stores the Keystone
admin password in the cloud database. By default this password is generated
randomly but, for testing purposes, can be set via the `admin-password`
configuration option. This option can also be used to view and change the
password post-deployment.

## Actions

This section covers Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions keystone`. If the charm is not
deployed then see file `actions.yaml`.

* `openstack-upgrade`
* `pause`
* `resume`
* `security-checklist`

## High availability

When more than one unit is deployed with the [hacluster][hacluster-charm]
application the charm will bring up an HA active/active cluster.

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases the hacluster subordinate charm is used to provide the
Corosync and Pacemaker backend HA functionality.

See [OpenStack high availability][cdg-ha-apps] in the [OpenStack Charms
Deployment Guide][cdg] for details.

### TLS

Communication between Keystone and cloud services (as well as the OpenStack
client) can be encrypted with TLS. Keystone also publishes API endpoints for
the cloud (e.g. cinder, glance, keystone, neutron, nova, and placement), which
may be TLS-based.

There are two methods for managing TLS keys and certificates:

1. with Vault
1. manually (via charm options)

Vault can set up private keys and server certificates for an application. It
can also store a central CA certificate for the cloud. See the
[vault][vault-charm] charm for more information.

Vault is the recommended method and is what will be covered here.

The private key and server certificate (and its signing) are enabled via a
relation made to the vault application:

    juju add-relation keystone:certificates vault:certificates

#### Other applications

Other applications can enable TLS by adding their own relation to Vault. Vault
will issue certificates to the application and Keystone will update the
corresponding API endpoint from HTTP to HTTPS.

For example, the Placement API:

    juju add-relation placement:certificates vault:certificates

> **Note**: API endpoints can be listed with `openstack catalog list`.

## Spaces

This charm supports the use of Juju Network Spaces, allowing the charm to be
bound to network space configurations managed directly by Juju. This is only
supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the network
separation of public, internal and admin endpoints.

Access to the underlying MySQL instance can also be bound to a specific space
using the shared-db relation.

To use this feature, use the --bind option when deploying the charm:

    juju deploy keystone --bind \
       "public=public-space \
        internal=internal-space \
        admin=admin-space \
        shared-db=internal-space"

Alternatively, these can also be provided as part of a Juju native bundle
configuration:

```yaml
    keystone:
      charm: cs:xenial/keystone
      num_units: 1
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space
        shared-db: internal-space
```

NOTE: Spaces must be configured in the underlying provider prior to attempting
to use them (i.e. see [MAAS spaces][ms]).

NOTE: Existing deployments using `os\-\*-network` configuration options will
continue to function; these options are preferred over any network space
binding provided if set.

## Policy Overrides

Policy overrides is an advanced feature that allows an operator to override the
default policy of an OpenStack service. The policies that the service supports,
the defaults it implements in its code, and the defaults that a charm may
include should all be clearly understood before proceeding.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy statements are placed in a YAML file. This file (or files) is then (ZIP)
compressed into a single file and used as an application resource. The override
is then enabled via a Boolean charm option.

Here are the essential commands (filenames are arbitrary):

    zip overrides.zip override-file.yaml
    juju attach-resource keystone policyd-override=overrides.zip
    juju config keystone use-policyd-override=true

See appendix [Policy Overrides][cdg-appendix-n] in the [OpenStack Charms
Deployment Guide][cdg] for a thorough treatment of this feature.

## Relations

The charm supports the following relations. They are primarily of use to
developers:

* `identity-admin`: Used by charms to obtain the credentials for the admin
  user. This is intended for charms that automatically provision users,
  tenants, etc.

* `identity-credentials`: Used by charms to obtain Keystone credentials without
  creating a service catalogue entry. Set 'username' only on the relation and
  Keystone will set defaults and return authentication details. Possible
  relation settings:

  * `username`: Username to be created.
  * `project`: Project (tenant) name to be created. Defaults to service's
               project.
  * `requested_roles`: Comma-delimited list of roles to be created.
  * `requested_grants`: Comma-delimited list of roles to be granted. Defaults
                        to Admin role.
  * `domain`: Keystone v3 domain the user will be created in. Defaults to the
              Default domain.

* `identity-notifications`: Used to broadcast messages to services listening on
  the corresponding interface.

* `identity-service`: Used by API endpoints to request an entry in the Keystone
  service catalogue and the endpoint template catalogue.

  > **Note**: The `identity-service` relation is not used by Horizon (see
    `keystone-service` instead).

  When a relation is established Keystone receives the following data from the
  requesting API endpoint:

  * `service_name`
  * `region`
  * `public_url`
  * `admin_url`
  * `internal_url`

  Keystone verifies that the requested service is supported (the list of
  supported services should remain updated). The following will occur for a
  supported service:

  1. an entry in the service catalogue is created
  1. an endpoint template is created
  1. an admin token is generated.

  The API endpoint receives the token and is informed of the ports that
  Keystone is listening on.

* `keystone-service`: Used only by Horizon. Horizon requests its configured
  default role and Keystone responds with a token. Horizon also receives the
  authentication and admin ports on which Keystone is listening.

* `nrpe-external-master`: Used to generate Nagios checks.

## Security Compliance config option "password-security-compliance"

The `password-security-compliance` configuration option sets the
`[security_compliance]` section of Keystone's configuration file.

The configuration option is a YAML dictionary, that is one level deep, with the
following keys (and value formats).

```yaml
lockout_failure_attempts: <int>
lockout_duration: <int>
disable_user_account_days_inactive: <int>
change_password_upon_first_use: <boolean>
password_expires_days: <int>
password_regex: <string>
password_regex_description: <string>
unique_last_password_count: <int>
minimum_password_age: <int>
```

It can be set by placing the keys and values in a file and then using the Juju
command:

    juju config keystone --file path/to/config.yaml

Note that, in this case, the `config.yaml` file requires the YAML key
`password-security-compliance:` with the desired config keys and values on the
following lines, indented for a dictionary.

> **Note**: Please ensure that the page [Security compliance and PCI-DSS][SCPD]
  is consulted before setting these options.

The charm will protect service accounts (accounts requested by other units that
are in the service domain) against being forced to change their password.
Operators should also ensure that any other accounts are protected as per the
above referenced note.

If the config value cannot be parsed as YAML and/or the options are not
able to be parsed as their indicated types then the charm will enter a blocked
state until the config value is changed.

## Token Support

As the keystone charm supports multiple releases of the OpenStack software, it
also supports two Keystone token systems: UUID and Fernet. The capabilities are:

- pre 'ocata': UUID tokens only.
- ocata and pike: UUID or Fernet tokens, configured via the 'token-provider'
  configuration parameter.
- rocky and later: Fernet tokens only.

Fernet tokens were added to OpenStack to solve the problem of Keystone being
required to persist tokens to a common database (cluster) like UUID tokens,
and solve the problem of size for PKI or PKIZ tokens.

For further information, please see [Fernet - Frequently Asked
Questions](https://docs.openstack.org/keystone/pike/admin/identity-fernet-token-faq.html).

### Theory of Operation

Fernet keys are used to generate tokens; they are generated by Keystone
and have an expiration date. The key repository is a directory, and each
key is an integer number, with the highest number being the primary key. Key
'0' is the staged key, that will be the next primary. Other keys are secondary
keys.

New tokens are only ever generated from the primary key, whilst the secondary
keys are used to validate existing tokens. The staging key is not used to
generate tokens but can be used to validate tokens as the staging key might be
the new primary key on the master due to a rotation and the keys have not yet
been synchronised across all the units.

Fernet keys need to be rotated at periodic intervals, and the keys need to be
synchronised to each of the other keystone units. Keys should only be rotated
on the master keystone unit and must be synchronised *before* they are rotated
again. *Over rotation* occurs if a unit rotates its keys such that there is
no suitable decoding key on another unit that can decode a token that has been
generated on the master. This happens if two key rotations are done on the
master before a synchronisation has been successfully performed. This should
be avoided. Over rotations can also cause validation keys to be removed
*before* a token's expiration which would result in failed validations.

There are 3 parts to the **Key Rotation Strategy**:

1. The rotation frequency
2. The token lifespan
3. The number of active keys

There needs to be at least 3 keys as a minimum. The actual number of keys is
determined by the *token lifespan* and the *rotation frequency*. The
*max_active_keys* must be one greater than the *token lifespan* / *rotation
frequency*

To quote from the [FAQ](https://docs.openstack.org/keystone/queens/admin/identity-fernet-token-faq.html):

        The number of max_active_keys for a deployment can be determined by
        dividing the token lifetime, in hours, by the frequency of rotation in
        hours and adding two. Better illustrated as:

### Configuring Key Lifetime

In the keystone charm, the _rotation frequency_ is calculated
automatically from the `token-expiration` and the `fernet-max-active-keys`
configuration parameters. For example, with an expiration of 24 hours and
6 active keys, the rotation frequency is calculated as:

```python
token_expiration = 24   # actually 3600, as it's in seconds
max_active_keys = 6
rotation_frequency = token_expiration / (max_active_keys - 2)
```

Thus, the `fernet-max-active-keys` can never be less than 3 (which is
enforced in the charm), which would make the rotation frequency the *same*
as the token expiration time.

NOTE: To increase the rotation frequency, _either_ increase
`fernet-max-active-keys` or reduce `token-expiration`, and, to decrease
rotation frequency, do the opposite.

NOTE: If the configuration parameters are used to significantly reduce the
key lifetime, then it is possible to over-rotate the verification keys
such that services will hold tokens that cannot be verified but haven't
yet expired. This should be avoided by only making small changes and
verifying that current tokens will still be able to be verified. In
particular, `fernet-max-active-keys` affects the rotation time.

### Upgrades

When an older keystone charm is upgraded to this version, NO change will
occur to the token system. That is, an ocata system will continue to use
UUID tokens. In order to change the token system to Fernet, change the
`token-provider` configuration item to `fernet`. This will switch the
token system over. There may be a small outage in the _control plane_,
but the running instances will be unaffected.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-keystone].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[hacluster-charm]: https://jaas.ai/hacluster
[vault-charm]: https://jaas.ai/vault
[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-appendix-n]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-policy-overrides.html
[lp-bugs-charm-keystone]: https://bugs.launchpad.net/charm-keystone/+filebug
[SCPD]: https://docs.openstack.org/keystone/latest/admin/configuration.html#security-compliance-and-pci-dss
[cdg-ha-apps]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#ha-applications
[upstream-keystone]: https://docs.openstack.org/keystone/latest/
[juju-docs-config-apps]: https://juju.is/docs/configuring-applications
[wiki-uca]: https://wiki.ubuntu.com/OpenStack/CloudArchive
[juju-docs-actions]: https://jaas.ai/docs/actions
[percona-cluster-charm]: https://jaas.ai/percona-cluster
[mysql-innodb-cluster-charm]: https://jaas.ai/mysql-innodb-cluster
[ms]: https://maas.io/docs/concepts-and-terms#heading--spaces
