#!/usr/bin/env python3
#
# Copyright 2019 Canonical Ltd
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

import configparser
import os
import sys

sys.path.append('.')

import charmhelpers.contrib.openstack.audits as audits
from charmhelpers.contrib.openstack.audits import (
    openstack_security_guide,
)


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def uses_sha256_for_hashing_tokens(audit_options):
    """Validate that SHA256 is used to hash tokens.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    section = audit_options['keystone-conf'].get('token')
    assert section is not None, "Missing section 'token'"
    algorithm = section.get("hash_algorithm")
    assert "SHA256" == algorithm, \
        "Weak hash algorithm used for hashing tokens: ".format(
            algorithm)


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),
              audits.since_openstack_release('keystone', 'juno'))
def check_max_request_body_size(audit_options):
    """Validate that a sane max_request_body_size is set.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    default = audit_options['keystone-conf'].get('DEFAULT', {})
    oslo_middleware = audit_options['keystone-conf'] \
        .get('oslo_middleware', {})
    # assert section is not None, "Missing section 'DEFAULT'"
    assert (default.get('max_request_body_size') or
            oslo_middleware.get('max_request_body_size') is not None), \
        "max_request_body_size should be set"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide))
def disable_admin_token(audit_options):
    """Validate that the admin token is disabled.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    default = audit_options['keystone-conf'].get('DEFAULT')
    assert default is not None, "Missing section 'DEFAULT'"
    assert default.get('admin_token') is None, \
        "admin_token should be unset"
    keystone_paste = _config_file('/etc/keystone/keystone-paste.ini')
    section = keystone_paste.get('filter:admin_token_auth')
    if section is not None:
        assert section.get('AdminTokenAuthMiddleware') is None, \
            'AdminTokenAuthMiddleware should be unset in keystone-paste.ini'


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide))
def insecure_debug_is_false(audit_options):
    """Valudaite that insecure_debug is false.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    section = audit_options['keystone-conf'].get('DEFAULT')
    assert section is not None, "Missing section 'DEFAULT'"
    insecure_debug = section.get('insecure_debug')
    if insecure_debug is not None:
        assert insecure_debug == "false", \
            "insecure_debug should be false"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),
              audits.since_openstack_release('keystone', 'pike'),
              audits.before_openstack_release('keystone', 'rocky'))
def uses_fernet_token(audit_options):
    """Validate that fernet tokens are used.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    section = audit_options['keystone-conf'].get('token')
    assert section is not None, "Missing section 'token'"
    assert "fernet" == section.get("provider"), \
        "Fernet tokens are not used"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),
              audits.since_openstack_release('keystone', 'rocky'))
def uses_fernet_token_after_default(audit_options):
    """Validate that fernet tokens are used.

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    section = audit_options['keystone-conf'].get('token')
    assert section is not None, "Missing section 'token'"
    provider = section.get("provider")
    if provider:
        assert "fernet" == provider, "Fernet tokens are not used"


def _config_file(path):
    """Read and parse config file at `path` as an ini file.

    :param path: Path of the file
    :type path: List[str]
    :returns: Parsed contents of the file at path
    :rtype Dict:
    """
    conf = configparser.ConfigParser()
    conf.read(os.path.join(*path))
    return dict(conf)


def main():
    config = {
        'config_path': '/etc/keystone',
        'config_file': 'keystone.conf',
        'audit_type': audits.AuditType.OpenStackSecurityGuide,
        'files': openstack_security_guide.FILE_ASSERTIONS['keystone'],
        'excludes': [
            'validate-uses-keystone',
            'validate-uses-tls-for-glance',
            'validate-uses-tls-for-keystone',
        ],
    }
    config['keystone-conf'] = _config_file(
        [config['config_path'], config['config_file']])
    return audits.action_parse_results(audits.run(config))

if __name__ == "__main__":
    sys.exit(main())
