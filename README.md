This charm provides Keystone, the Openstack identity service.  It's target
platform is Ubuntu Precise + Openstack Essex.  This has not been tested
using Oneiric + Diablo.

It provides three interfaces.
 
    - identity-service:  Openstack API endpoints request an entry in the 
      Keystone service catalog + endpoint template catalog.  When a relation
      is established, Keystone receives: service name, region, public_url,
      admin_url and internal_url.  It first checks that the requested service
      is listed as a supported service.  This list should stay updated to
      support current Openstack core services.  If the services is supported,
      a entry in the service catalog is created, an endpoint template is
      created and a admin token is generated.   The other end of the relation
      recieves the token as well as info on which ports Keystone is listening.

    - keystone-service:  This is currently only used by Horizon/dashboard
      as its interaction with Keystone is different from other Openstack API
      servicies.  That is, Horizon requests a Keystone role and token exists.
      During a relation, Horizon requests its configured default role and
      Keystone responds with a token and the auth + admin ports on which
      Keystone is listening.

    - identity-admin:  Charms use this relation to obtain the credentials
      for the admin user.  This is intended for charms that automatically
      provision users, tenants, etc. or that otherwise automate using the
      Openstack cluster deployment.

Keystone requires a database.  By default, a local sqlite database is used.
The charm supports relations to a shared-db via mysql-shared interface.  When
a new data store is configured, the charm ensures the minimum administrator
credentials exist (as configured via charm configuration)

VIP is only required if you plan on multi-unit clusterming. The VIP becomes a highly-available API endpoint.

Deploying from source
---------------------

The minimal openstack-origin-git config required to deploy from source is:

  openstack-origin-git:
      "{'keystone':
           {'repository': 'git://git.openstack.org/openstack/keystone.git',
            'branch': 'stable/icehouse'}}"

If you specify a 'requirements' repository, it will be used to update the
requirements.txt files of all other git repos that it applies to, before
they are installed:

  openstack-origin-git:
      "{'requirements':
           {'repository': 'git://git.openstack.org/openstack/requirements.git',
            'branch': 'master'},
        'keystone':
           {'repository': 'git://git.openstack.org/openstack/keystone.git',
            'branch': 'master'}}"

Note that there are only two key values the charm knows about for the outermost
dictionary: 'keystone' and 'requirements'. These repositories must correspond to
these keys. If the requirements repository is specified, it will be installed
first. The keystone repository is always installed last.  All other repostories
will be installed in between.

NOTE(coreycb): The following is temporary to keep track of the full list of
current tip repos (may not be up-to-date).

  openstack-origin-git:
      "{'requirements':
           {'repository': 'git://git.openstack.org/openstack/requirements.git',
            'branch': 'master'},
        'keystonemiddleware:
           {'repository': 'git://git.openstack.org/openstack/keystonemiddleware.git',
            'branch: 'master'},
        'oslo-concurrency':
           {'repository': 'git://git.openstack.org/openstack/oslo.concurrency.git',
            'branch: 'master'},
        'oslo-config':
           {'repository': 'git://git.openstack.org/openstack/oslo.config.git',
            'branch: 'master'},
        'oslo-db':
           {'repository': 'git://git.openstack.org/openstack/oslo.db.git',
            'branch: 'master'},
        'oslo-i18n':
           {'repository': 'git://git.openstack.org/openstack/oslo.i18n.git',
            'branch: 'master'},
        'oslo-serialization':
           {'repository': 'git://git.openstack.org/openstack/oslo.serialization.git',
            'branch: 'master'},
        'oslo-utils':
           {'repository': 'git://git.openstack.org/openstack/oslo.utils.git',
            'branch: 'master'},
        'pbr':
           {'repository': 'git://git.openstack.org/openstack-dev/pbr.git',
            'branch: 'master'},
        'python-keystoneclient':
           {'repository': 'git://git.openstack.org/openstack/python-keystoneclient.git',
            'branch: 'master'},
        'sqlalchemy-migrate':
           {'repository': 'git://git.openstack.org/stackforge/sqlalchemy-migrate.git',
            'branch: 'master'},
        'keystone':
           {'repository': 'git://git.openstack.org/openstack/keystone.git',
            'branch': 'master'}}"
