#!/usr/bin/env python3
# Copyright 2018 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import print_function

import os
import sys
import time

dir_path = os.path.dirname(os.path.realpath(__file__))
hooks_path = os.path.abspath(os.path.join(dir_path, "..", "hooks"))
root_path = os.path.abspath(os.path.join(dir_path, ".."))

for p in [hooks_path, root_path]:
    if p not in sys.path:
        sys.path.append(p)

# now we can import charm related items
import charmhelpers.core.hookenv

import keystone_utils


def cli_log(msg, level=charmhelpers.core.hookenv.INFO):
    """Helper function to write log message to stdout/stderr for CLI usage."""
    if level == charmhelpers.core.hookenv.DEBUG:
        return charmhelpers.core.hookenv.log(msg, level=level)
    elif level in [charmhelpers.core.hookenv.ERROR,
                   charmhelpers.core.hookenv.WARNING]:
        output = sys.stderr
    else:
        output = sys.stdout

    print('{}: {}'.format(time.ctime(), msg), file=output)


# the rotate_and_sync_keys() function checks for leadership AND whether to
# rotate the keys or not.
if __name__ == "__main__":
    keystone_utils.fernet_keys_rotate_and_sync(log_func=cli_log)
