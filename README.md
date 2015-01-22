Overview
========

This charm provides Keystone, the Openstack identity service. It's target
platform is (ideally) Ubuntu LTS + Openstack.

Usage
=====

The following interfaces are provided:

    - nrpe-external-master: Used to generate Nagios checks.

    - identity-service: Openstack API endpoints request an entry in the 
      Keystone service catalog + endpoint template catalog. When a relation
      is established, Keystone receives: service name, region, public_url,
      admin_url and internal_url. It first checks that the requested service
      is listed as a supported service. This list should stay updated to
      support current Openstack core services. If the service is supported,
      an entry in the service catalog is created, an endpoint template is
      created and a admin token is generated. The other end of the relation
      receives the token as well as info on which ports Keystone is listening
      on.

    - keystone-service: This is currently only used by Horizon/dashboard
      as its interaction with Keystone is different from other Openstack API
      services. That is, Horizon requests a Keystone role and token exists.
      During a relation, Horizon requests its configured default role and
      Keystone responds with a token and the auth + admin ports on which
      Keystone is listening.

    - identity-admin: Charms use this relation to obtain the credentials
      for the admin user. This is intended for charms that automatically
      provision users, tenants, etc. or that otherwise automate using the
      Openstack cluster deployment.

    - identity-notifications: Used to broadcast messages to any services
      listening on the interface.

Database
--------

Keystone requires a database. By default, a local sqlite database is used.
The charm supports relations to a shared-db via mysql-shared interface. When
a new data store is configured, the charm ensures the minimum administrator
credentials exist (as configured via charm configuration)

HA/Clustering
-------------

VIP is only required if you plan on multi-unit clustering (requires relating
with hacluster charm). The VIP becomes a highly-available API endpoint.

SSL/HTTPS
---------

This charm also supports SSL and HTTPS endpoints. In order to ensure SSL
certificates are only created once and distributed to all units, one unit gets
elected as an ssl-cert-master. One side-effect of this is that as units are
scaled-out the currently elected leader needs to be running in order for nodes
to sync certificates. This 'feature' is to work around the lack of native
leadership election via Juju itself, a feature that is due for release some
time soon but until then we have to rely on this. Also, if a keystone unit does
go down, it must be removed from Juju i.e.

    juju destroy-unit keystone/<unit-num>

Otherwise it will be assumed that this unit may come back at some point and
therefore must be know to be in-sync with the rest before continuing.

