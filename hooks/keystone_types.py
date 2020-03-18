#!/usr/bin/env python2

# Copyright 2020 Canonical Ltd
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

# NOTE(fnordahl): This file needs to remain Python2 as it is used both by the
# charm code which is Python3 and the special ``manager.py`` script that is in
# place to support both Python2 and Python3 systems with the same codebase.
#
# The need for jumping through these hoops come from classic charms being
# deployed without any form of Python environment with direct dependencies.
# Subsequently we live at the grace of whatever dependencies our payload has
# in the running system.  This may change underneath us as we upgrade between
# UCA pockets and across series.

import collections


CharmCredentials = collections.namedtuple(
    'CharmCredentials',
    (
        'username',
        'password',
        'system_scope',
        'project_name',         # For V2 and pre system scope compatibility
        'project_domain_name',  # For Mitaka -> Pike (pre system scope)
        'user_domain_name',     # For Mitaka -> Pike (pre system scope)
    ),
)
