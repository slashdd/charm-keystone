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

# NOTE(tinwood): This file needs to remain Python2 as it uses keystoneclient
# from the payload software to do it's work.

from __future__ import print_function

import json
import os
import stat
import sys
import time

from keystoneclient.v2_0 import client
from keystoneclient.v3 import client as keystoneclient_v3
from keystoneclient.auth import token_endpoint
from keystoneclient import session, exceptions

import uds_comms as uds


_usage = """This file is called from the keystone_utils.py file to implement
various keystone calls and functions.  It is called with one parameter which is
the path to a Unix Domain Socket file.

The messages passed to the this process from the keystone_utils.py includes the
following keys:

{
    'path': The api path on the keystone manager object.
    'api_version': the keystone API version to use.
    'api_local_endpoint': the local endpoint to connect to.
    'admin_token': the admin token to use with keystone.
    'args': the non-keyword argument to supply to the keystone manager call.
    'kwargs': any keyword args to supply to the keystone manager call.
}

The result of the call, or an error, is returned as a json encoded result in
the same file that sent the arguments.

{
    'result': <whatever the result of the function call was>
    'error': <if an error occured, the text of the error
}

This system is currently needed to decouple the majority of the charm from the
underlying package being used for keystone.
"""

JSON_ENCODE_OPTIONS = dict(
    sort_keys=True,
    allow_nan=False,
    indent=None,
    separators=(',', ':'),
)


# Early versions of keystoneclient lib do not have an explicit
# ConnectionRefused
if hasattr(exceptions, 'ConnectionRefused'):
    econnrefused = exceptions.ConnectionRefused
else:
    econnrefused = exceptions.ConnectionError


def _get_keystone_manager_class(endpoint, token, api_version):
    """Return KeystoneManager class for the given API version
    @param endpoint: the keystone endpoint to point client at
    @param token: the keystone admin_token
    @param api_version: version of the keystone api the client should use
    @returns keystonemanager class used for interrogating keystone
    """
    if api_version == 2:
        return KeystoneManager2(endpoint, token)
    if api_version == 3:
        return KeystoneManager3(endpoint, token)
    raise ValueError('No manager found for api version {}'.format(api_version))


def retry_on_exception(num_retries, base_delay=0, exc_type=Exception):
    """If the decorated function raises exception exc_type, allow num_retries
    retry attempts before raise the exception.
    """
    def _retry_on_exception_inner_1(f):
        def _retry_on_exception_inner_2(*args, **kwargs):
            retries = num_retries
            multiplier = 1
            while True:
                try:
                    return f(*args, **kwargs)
                except exc_type:
                    if not retries:
                        raise

                delay = base_delay * multiplier
                multiplier += 1
                print("Retrying '{0}' {1} more times (delay={2})"
                      .format(f.__name__, retries, delay))
                retries -= 1
                if delay:
                    time.sleep(delay)

        return _retry_on_exception_inner_2

    return _retry_on_exception_inner_1


@retry_on_exception(5, base_delay=3, exc_type=econnrefused)
def get_keystone_manager(endpoint, token, api_version=None):
    """Return a keystonemanager for the correct API version

    If api_version has not been set then create a manager based on the endpoint
    Use this manager to query the catalogue and determine which api version
    should actually be being used. Return the correct client based on that.
    Function is wrapped in a retry_on_exception to catch the case where the
    keystone service is still initialising and not responding to requests yet.
    XXX I think the keystone client should be able to do version
        detection automatically so the code below could be greatly
        simplified

    @param endpoint: the keystone endpoint to point client at
    @param token: the keystone admin_token
    @param api_version: version of the keystone api the client should use
    @returns keystonemanager class used for interrogating keystone
    """
    if api_version:
        return _get_keystone_manager_class(endpoint, token, api_version)
    else:
        if 'v2.0' in endpoint.split('/'):
            manager = _get_keystone_manager_class(endpoint, token, 2)
        else:
            manager = _get_keystone_manager_class(endpoint, token, 3)
        if endpoint.endswith('/'):
            base_ep = endpoint.rsplit('/', 2)[0]
        else:
            base_ep = endpoint.rsplit('/', 1)[0]
        svc_id = None
        for svc in manager.api.services.list():
            if svc.type == 'identity':
                svc_id = svc.id
                break
        version = None
        for ep in manager.api.endpoints.list():
            if ep.service_id == svc_id and hasattr(ep, 'adminurl'):
                version = ep.adminurl.split('/')[-1]
                break
        if version and version == 'v2.0':
            new_ep = base_ep + "/" + 'v2.0'
            return _get_keystone_manager_class(new_ep, token, 2)
        elif version and version == 'v3':
            new_ep = base_ep + "/" + 'v3'
            return _get_keystone_manager_class(new_ep, token, 3)
        else:
            return manager


class KeystoneManager(object):

    def resolved_api_version(self):
        """Used by keystone_utils.py to determine which endpoint template
        to create based on the current endpoint which needs to actually be done
        in get_keystone_manager() in this file.

        :returns: the current api version
        :rtype: int
        """
        return self.api_version

    def resolve_domain_id(self, name):
        pass

    def resolve_role_id(self, name):
        """Find the role_id of a given role"""
        roles = [r._info for r in self.api.roles.list()]
        for r in roles:
            if name.lower() == r['name'].lower():
                return r['id']

    def resolve_service_id(self, name, service_type=None):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if service_type:
                if (name.lower() == s['name'].lower() and
                        service_type == s['type']):
                    return s['id']
            else:
                if name.lower() == s['name'].lower():
                    return s['id']

    def resolve_service_id_by_type(self, type):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if type == s['type']:
                return s['id']

    def delete_service_by_id(self, service_id):
        """Delete a service by the service id"""
        self.api.services.delete(service_id)

    def list_services(self):
        """Return a list of services (dictionary items)"""
        return [s.to_dict() for s in self.api.services.list()]

    def create_service(self, service_name, service_type, description):
        """Create a service using the api"""
        self.api.services.create(service_name,
                                 service_type,
                                 description=description)

    def list_endpoints(self):
        """Return a list of endpoints (dictionary items)"""
        return [e.to_dict() for e in self.api.endpoints.list()]

    def create_role(self, name):
        """Create the role by name."""
        self.api.roles.create(name=name)


class KeystoneManager2(KeystoneManager):

    def __init__(self, endpoint, token):
        self.api_version = 2
        self.api = client.Client(endpoint=endpoint, token=token)

    def resolve_user_id(self, name, user_domain=None):
        """Find the user_id of a given user"""
        users = [u._info for u in self.api.users.list()]
        for u in users:
            if name.lower() == u['name'].lower():
                return u['id']

    def create_endpoints(self, region, service_id, publicurl, adminurl,
                         internalurl):
        self.api.endpoints.create(region=region, service_id=service_id,
                                  publicurl=publicurl, adminurl=adminurl,
                                  internalurl=internalurl)

    def delete_endpoint_by_id(self, endpoint_id):
        """Delete an endpoint by the endpoint_id"""
        self.api.endpoints.delete(endpoint_id)

    def tenants_list(self):
        return self.api.tenants.list()

    def resolve_tenant_id(self, name, domain=None):
        """Find the tenant_id of a given tenant"""
        tenants = [t._info for t in self.api.tenants.list()]
        for t in tenants:
            if name.lower() == t['name'].lower():
                return t['id']

    def create_tenant(self, tenant_name, description, domain='default'):
        self.api.tenants.create(tenant_name=tenant_name,
                                description=description)

    def delete_tenant(self, tenant_id):
        self.api.tenants.delete(tenant_id)

    def create_user(self, name, password, email, tenant_id=None,
                    domain_id=None):
        self.api.users.create(name=name,
                              password=password,
                              email=email,
                              tenant_id=tenant_id)

    def user_exists(self, name, domain=None):
        if domain is not None:
            raise ValueError("For keystone v2, domain cannot be set")
        if self.resolve_user_id(name):
            users = manager.api.users.list()
            for user in users:
                if user.name.lower() == name.lower():
                    return True
        return False

    def update_password(self, user, password):
        self.api.users.update_password(user=user, password=password)

    def roles_for_user(self, user_id, tenant_id=None, domain_id=None):
        roles = self.api.roles.roles_for_user(user_id, tenant_id)
        return [r.to_dict() for r in roles]

    def add_user_role(self, user, role, tenant, domain):
        self.api.roles.add_user_role(user=user, role=role, tenant=tenant)


class KeystoneManager3(KeystoneManager):

    def __init__(self, endpoint, token):
        self.api_version = 3
        keystone_auth_v3 = token_endpoint.Token(endpoint=endpoint, token=token)
        keystone_session_v3 = session.Session(auth=keystone_auth_v3)
        self.api = keystoneclient_v3.Client(session=keystone_session_v3)

    def resolve_tenant_id(self, name, domain=None):
        """Find the tenant_id of a given tenant"""
        if domain:
            domain_id = self.resolve_domain_id(domain)
        tenants = [t._info for t in self.api.projects.list()]
        for t in tenants:
            if name.lower() == t['name'].lower() and \
               (domain is None or t['domain_id'] == domain_id):
                return t['id']

    def resolve_domain_id(self, name):
        """Find the domain_id of a given domain"""
        domains = [d._info for d in self.api.domains.list()]
        for d in domains:
            if name.lower() == d['name'].lower():
                return d['id']

    def resolve_user_id(self, name, user_domain=None):
        """Find the user_id of a given user"""
        domain_id = None
        if user_domain:
            domain_id = self.resolve_domain_id(user_domain)
        for user in self.api.users.list(domain=domain_id):
            if name.lower() == user.name.lower():
                if user_domain:
                    if domain_id == user.domain_id:
                        return user.id
                else:
                    return user.id

    def create_endpoints(self, region, service_id, publicurl, adminurl,
                         internalurl):
        self.api.endpoints.create(service_id, publicurl, interface='public',
                                  region=region)
        self.api.endpoints.create(service_id, adminurl, interface='admin',
                                  region=region)
        self.api.endpoints.create(service_id, internalurl,
                                  interface='internal', region=region)

    def create_endpoint_by_type(self, service_id, endpoint, interface, region):
        """Create an endpoint by interface (type), where _interface is
        'internal', 'admin' or 'public'.
        """
        self.api.endpoints.create(
            service_id, endpoint, interface=interface, region=region)

    def tenants_list(self):
        return self.api.projects.list()

    def create_domain(self, domain_name, description):
        self.api.domains.create(domain_name, description=description)

    def create_tenant(self, tenant_name, description, domain='default'):
        domain_id = self.resolve_domain_id(domain)
        self.api.projects.create(tenant_name, domain_id,
                                 description=description)

    def delete_tenant(self, tenant_id):
        self.api.projects.delete(tenant_id)

    def create_user(self, name, password, email, tenant_id=None,
                    domain_id=None):
        if not domain_id:
            domain_id = self.resolve_domain_id('default')
        if tenant_id:
            self.api.users.create(name,
                                  domain=domain_id,
                                  password=password,
                                  email=email,
                                  project=tenant_id)
        else:
            self.api.users.create(name,
                                  domain=domain_id,
                                  password=password,
                                  email=email)

    def user_exists(self, name, domain=None):
        domain_id = None
        if domain:
            domain_id = manager.resolve_domain_id(domain)
            if not domain_id:
                raise ValueError(
                    'Could not resolve domain_id for {} when checking if '
                    ' user {} exists'.format(domain, name))
        if manager.resolve_user_id(name, user_domain=domain):
            users = manager.api.users.list(domain=domain_id)
            for user in users:
                if user.name.lower() == name.lower():
                    # In v3 Domains are seperate user namespaces so need to
                    # check that the domain matched if provided
                    if domain:
                        if domain_id == user.domain_id:
                            return True
                    else:
                        return True
        return False

    def update_password(self, user, password):
        self.api.users.update(user, password=password)

    def get_user_details_dict(self, user, **kwargs):
        """Get the user details dictionary for a user.

        This fetches the user details for a user and domain or domain_id.
        It uses the lowercase name for the user; all users as far as the
        keystone charm are concerned are the same if lower cased.

        :param user: the user name to look for.
        :type user: str
        :returns: a dictionary of key:value pairs representing the user
        :rtype: Optional[Dict[str, ANY]]
        :raises: RuntimeError if no domain or domain_id is passed.
                 ValueError if the domain_id cannot be resolved
        """
        domain_id = kwargs.get('domain_id', None)
        domain = kwargs.get('domain', None)
        if not domain_id:
            if not domain:
                raise RuntimeError(
                    "Can't resolve a domain as no domain or domain_id "
                    "supplid.")
            domain_id = manager.resolve_domain_id(domain)
            if not domain_id:
                raise ValueError(
                    'Could not resolve domain_id for {} when checking if '
                    ' user {} exists'.format(domain, user))
        for u in self.api.users.list(domain=domain_id):
            if user.lower() == u.name.lower():
                if domain_id == u.domain_id:
                    return u.to_dict()
        return None

    def update_user(self, user, **kwargs):
        """Update the user with data from the **kwargs.

        It is the responsibility of the caller to fully define the user
        that needs to be udpated.  e.g. preferably the user is a
        :class:`keystoneclient.v3.users.User`

        :param user: The user to be updated.
        :type user: Union[str, keystoneclient.v3.users.User]
        :params **kwargs: the keys, values to be udpated.
        :type **kwargs: Dict[str, str]
        :returns: the dictionary representation of the updated user
        :rtype: Dict[str, ANY]
        """
        res = self.api.users.update(user, **kwargs)
        return res.to_dict()

    def list_users_for_domain(self, domain=None, domain_id=None):
        """Return a list of all the users in a domain.

        This returns a list of the users in the specified domain_id or
        domain_id resolved from the domain name.  The return value is a
        restricted list of dictionary items:

            {
                'name': <str>
                'id': <str>
            }

        One of either the :param:`domain` or :param:`domain_id` must be
        supplied or otherwise the function raises a RuntimeError.

        :param domain: The domain name.
        :type domain: Optional[str]
        :param domain_id: The domain_id string
        :type domain_id: Optional[str]
        :returns: a list of user dictionaries in the domain
        :rtype: List[Dict[str, ANY]]
        :raises: RuntimeError if no domain or domain_id is passed.
                 ValueError if the domain_id cannot be resolved from the domain
        """
        if domain is None and domain_id is None:
            raise RuntimeError("Must supply either domain or domain_id param")
        domain_id = domain_id or manager.resolve_domain_id(domain)
        if domain_id is None:
            raise ValueError(
                'Could not resolve domain_id for {}.'.format(domain))
        users = [{'name': u.name, 'id': u.id}
                 for u in self.api.users.list(domain=domain_id)]
        return users

    def roles_for_user(self, user_id, tenant_id=None, domain_id=None):
        # Specify either a domain or project, not both
        if domain_id:
            roles = self.api.roles.list(user_id, domain=domain_id)
        else:
            roles = self.api.roles.list(user_id, project=tenant_id)
        return [r.to_dict() for r in roles]

    def add_user_role(self, user, role, tenant, domain):
        # Specify either a domain or project, not both
        if domain:
            self.api.roles.grant(role, user=user, domain=domain)
        if tenant:
            self.api.roles.grant(role, user=user, project=tenant)

    def find_endpoint_v3(self, interface, service_id, region):
        found_eps = []
        for ep in self.api.endpoints.list():
            if ep.service_id == service_id and ep.region == region and \
                    ep.interface == interface:
                found_eps.append(ep)
        return [e.to_dict() for e in found_eps]

    def delete_old_endpoint_v3(self, interface, service_id, region, url):
        eps = self.find_endpoint_v3(interface, service_id, region)
        for ep in eps:
            # if getattr(ep, 'url') != url:
            if ep.get('url', None) != url:
                # self.api.endpoints.delete(ep.id)
                self.api.endpoints.delete(ep['id'])
                return True
        return False


# the following functions are proxied from keystone_utils, so that a Python3
# charm can work with a Python2 keystone_client (i.e. in the case of a snap
# installed payload

# used to provide a singleton if the credentials for the keystone_manager
# haven't changed.
_keystone_manager = dict(
    api_version=None,
    api_local_endpoint=None,
    admin_token=None,
    manager=None)


def get_manager(api_version=None, api_local_endpoint=None, admin_token=None):
    """Return a keystonemanager for the correct API version

    This function actually returns a singleton of the right kind of
    KeystoneManager (v2 or v3).  If the api_version, api_local_endpoint and
    admin_token haven't changed then the current _keystone_manager object is
    returned, otherwise a new one is created (and thus the old one goes out of
    scope and is closed).  This is to that repeated calls to get_manager(...)
    only results in a single authorisation request if the details don't change.
    This is to speed up calls from the keystone charm into keystone and make
    the charm more performant.  It's hoped that the complexity/performance
    trade-off is a good choice.

    :param api_verion: The version of the api to use or None.  if None then the
        version is determined from the api_local_enpoint variable.
    :param api_local_endpoint: where to find the keystone API
    :param admin_token: the token used for authentication.
    :raises: RuntimeError if api_local_endpoint or admin_token is not set.
    :returns: a KeystoneManager derived class (possibly the singleton).
    """
    if api_local_endpoint is None:
        raise RuntimeError("get_manager(): api_local_endpoint is not set")
    if admin_token is None:
        raise RuntimeError("get_manager(): admin_token is not set")
    global _keystone_manager
    if (api_version == _keystone_manager['api_version'] and
            api_local_endpoint == _keystone_manager['api_local_endpoint'] and
            admin_token == _keystone_manager['admin_token']):
        return _keystone_manager['manager']
    # only retain the params IF getting the manager actually works
    _keystone_manager['manager'] = get_keystone_manager(
        api_local_endpoint, admin_token, api_version)
    _keystone_manager['api_version'] = api_version
    _keystone_manager['api_local_endpoint'] = api_local_endpoint
    _keystone_manager['admin_token'] = admin_token
    return _keystone_manager['manager']


class ManagerException(Exception):
    pass


"""
In the following code, there is a slightly unusual construction:

        _callable = manager
        for attr in spec['path']:
            _callable = getattr(_callable, attr)

What this does is allow the calling file to make it look like it was just
calling a deeply nested function in a class hierarchy.

So in the calling file, you get something like this:

    manager = get_manager()
    manager.some_function(a, b, c, y=10)

And that gets translated by the calling code into a json structure
that looks like:

{
    "path": ['some_function'],
    "args": [1, 2, 3],
    "kwargs": {'y': 10},
    ... other bits for tokens, etc ...
}

If it was `manager.some_class.some_function(a, b, c, y=10)` then the "path"
would equal ['some_class', 'some_function'].

So what these three lines do is replicate the call on the KeystoneManager class
in this file, but successively grabbing attributes down/into the class using
the path as the attributes at each level.
"""

if __name__ == '__main__':
    # This script needs 1 argument which is the unix domain socket though which
    # it communicates with the caller.  The program stays running until it is
    # sent a 'STOP' command by the caller, or is just killed.
    if len(sys.argv) != 2:
        raise RuntimeError(
            "{} called without 2 arguments: must pass the filename of the fifo"
            .format(__file__))
    filename = sys.argv[1]
    if not stat.S_ISSOCK(os.stat(filename).st_mode):
        raise RuntimeError(
            "{} called with {} but it is not a Unix domain socket"
            .format(__file__, filename))

    uds_client = uds.UDSClient(filename)
    uds_client.connect()
    # endless loop whilst we process messages from the caller
    while True:
        try:
            result = None
            data = uds_client.receive()
            if data == "QUIT" or data is None:
                break
            spec = json.loads(data)
            manager = get_manager(
                api_version=spec['api_version'],
                api_local_endpoint=spec['api_local_endpoint'],
                admin_token=spec['admin_token'])
            _callable = manager
            for attr in spec['path']:
                _callable = getattr(_callable, attr)
            # now make the call and return the arguments
            result = {'result': _callable(*spec['args'], **spec['kwargs'])}
        except exceptions.InternalServerError as e:
            # we've hit a 500 error, which is bad, and really we want the
            # parent process to restart us to try again.
            print(str(e))
            result = {'error': str(e),
                      'retry': True}
        except uds.UDSException as e:
            print(str(e))
            import traceback
            traceback.print_exc()
            try:
                uds_client.close()
            except Exception:
                pass
            sys.exit(1)
        except ManagerException as e:
            # deal with sending an error back.
            print(str(e))
            import traceback
            traceback.print_exc()
            result = {'error', str(e)}
        except Exception as e:
            print("{}: something went wrong: {}".format(__file__, str(e)))
            import traceback
            traceback.print_exc()
            result = {'error': str(e)}
        finally:
            if result is not None:
                result_json = json.dumps(result, **JSON_ENCODE_OPTIONS)
                uds_client.send(result_json)

    # normal exit
    exit(0)
