# Copyright 2016 Intel Corporation
# Copyright 2014 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
import os
from ironic.common.i18n import _

opts = [
    cfg.StrOpt('terminal',
               default='shellinaboxd',
               help=_('Path to serial console terminal program. Used only '
                      'by Shell In A Box console.')),
    cfg.StrOpt('terminal_cert_dir',
               help=_('Directory containing the terminal SSL cert (PEM) for '
                      'serial console access. Used only by Shell In A Box '
                      'console.')),
    cfg.StrOpt('terminal_pid_dir',
               help=_('Directory for holding terminal pid files. '
                      'If not specified, the temporary directory '
                      'will be used.')),
    cfg.IntOpt('subprocess_checking_interval',
               default=1,
               help=_('Time interval (in seconds) for checking the status of '
                      'console subprocess.')),
    cfg.IntOpt('subprocess_timeout',
               default=10,
               help=_('Time (in seconds) to wait for the console subprocess '
                      'to start.')),
    cfg.IntOpt('socket_gid',
               default=os.getgid(),
               help=_('The group id of a potentially created socket')),
    cfg.StrOpt('socket_permission',
               default='0500',
               help=_('Permissions of created unix sockets (octal)')),
    cfg.StrOpt('terminal_url_scheme',
               default='%(scheme)s://%(host)s:%(port)s',
               help=_('Url to the proxy')),
    cfg.StrOpt('ssh_command_pattern',
               default='sshpass -f %(pw_file)s ssh -l %(username)s %(address)s',
               help=_('Command pattern to establish a ssh connection')),
    cfg.StrOpt('url_auth_digest_secret',
               default='',
               help=_('Secret to hash the authentication token with')),
    cfg.StrOpt('url_auth_digest_algorithm',
               default='md5:base64',
               help=_('The digest algorithm (any python hash, followed by either :base64, or :hex')),
    cfg.IntOpt('url_auth_digest_expiry',
               default=900,
               help=_('The validity of the token in seconds')),
    cfg.StrOpt('url_auth_digest_pattern',
               default='%(expiry)s%(uuid)s %(secret)s',
               help=_('Python string formatting pattern, with expiry, uuid, and secret')),
]


def register_opts(conf):
    conf.register_opts(opts, group='console')
