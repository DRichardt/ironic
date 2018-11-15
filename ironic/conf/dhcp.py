# Copyright 2016 Intel Corporation
# Copyright 2014 Rackspace, Inc.
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

from ironic.common.i18n import _

opts = [
    cfg.StrOpt('dhcp_provider',
               default='neutron',
               help=_('DHCP provider to use. "neutron" uses Neutron, and '
                      '"none" uses a no-op provider.')),
    cfg.BoolOpt('ipxe_no_pxedhcp',
                default=False,
                help=_('If the dhcp provider is authoritative and there is no'
                       ' ProxyDHCP server'))
]


def register_opts(conf):
    conf.register_opts(opts, group='dhcp')
