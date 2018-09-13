#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.drivers import base
from ironic.drivers.modules.drac import common as drac_common


LOG = logging.getLogger(__name__)

drac_utils = importutils.try_import('dracclient.utils')

DRAC_VNC_PROPERTIES = {
    'drac_vnc_port': _("Optional. Integer from 1024 to 65535. "
                       "Default is 5901."),
    'drac_vnc_timeout': _("Optional. Integer from 60 to 10800 (in seconds). "
                          "Default is 300."),
    'drac_vnc_ssl_bitlength': _("Optional. One of ['disabled', 'auto', "
                                "'128bit', '168bit', '256bit']. "
                                "Default is 'disabled'."),
    'drac_vnc_password': _("Optional. Up to 8 characters. Defaults to empty.")
}


# TODO(pas-ha): propose iDRACCard[Service|View] mgmt to python-dracclient
class iDRACCard(object):

    def __init__(self, name):
        self.name = name

    @property
    def uri(self):
        return ('http://schemas.dell.com/wbem/wscim/1/cim-schema/2/%s' %
                self.resource)

    @property
    def resource(self):
        return 'DCIM_iDRACCard%s' % self.name


CARD_VIEW = iDRACCard('View')
CARD_SRV = iDRACCard('Service')
CARD_ENUM = iDRACCard('Enumeration')
CARD_INT = iDRACCard('Integer')
CARD_STR = iDRACCard('String')

VNC = 'VNCServer.1'
iDRAC_FQDD = 'iDRAC.Embedded.1'
CARD_SRV_SELECT = {'CreationClassName': CARD_SRV.resource,
                   'Name': CARD_SRV.resource.replace('_', ':'),
                   'SystemCreationClassName': 'DCIM_ComputerSystem',
                   'SystemName': 'DCIM:ComputerSystem'}

SSL_BITLENGTH_MAP = {'disabled': 'Disabled',
                     'auto': 'Auto Negotiate',
                     '128bit': '128-Bit or higher',
                     '168bit': '168-Bit or higher',
                     '256bit': '256-Bit or higher'}


def _validate_int_with_range(num, range_min, range_max):
    num = int(num)
    if num < range_min or num > range_max:
        raise ValueError
    else:
        return num


def parse_vnc_driver_info(node):
    d_info = node.driver_info
    p_info = {}
    errors = []
    port = d_info.get('drac_vnc_port', '5901')
    try:
        port = _validate_int_with_range(port, 1024, 65535)
    except ValueError:
        errors.append(_("VNC port is not an integer or out of range."))
    else:
        p_info['drac_vnc_port'] = port

    timeout = d_info.get('drac_vnc_timeout', '300')
    try:
        port = _validate_int_with_range(port, 60, 10800)
    except ValueError:
        errors.append(_("VNC timeout is not an integer or out of range."))
    else:
        p_info['drac_vnc_timeout'] = timeout

    password = d_info.get('drac_vnc_password')
    if password == "":
        password = None
    if password is not None:
        try:
            password = str(password)
        except UnicodeEncodeError:
            errors.append(_("VNC password contains non-ASCII characters"))
        else:
            if len(password) > 8:
                errors.append(_("VNC password too long (8 characters max)."))
            else:
                p_info['drac_vnc_password'] = password
    else:
        p_info['drac_vnc_password'] = password

    ssl = d_info.get('drac_vnc_ssl_bitlength', 'disabled')
    if ssl not in SSL_BITLENGTH_MAP:
        errors.append(_("SSL bit length has incorrect value "
                        "(must be one of %s)") % list(SSL_BITLENGTH_MAP))
    else:
        p_info['drac_vnc_ssl_bitlength'] = ssl

    if errors:
        msg = (_('The following errors were encountered while parsing '
                 'driver_info:\n%s') % '\n'.join(errors))
        raise exception.InvalidParameterValue(msg)
    return p_info


def _make_vnc_props(name, value):
    # TODO(pas-ha) get card Target FQDD from iDRAC?
    return {'Target': iDRAC_FQDD,
            'AttributeName': '#'.join([VNC, name]),
            'AttributeValue': value}


def _change_vnc_property(dracclient, name, value):
    dracclient.client.invoke(CARD_SRV.uri,
                             'SetAttribute',
                             selectors=CARD_SRV_SELECT,
                             properties=_make_vnc_props(name, value),
                             expected_return_value=drac_utils.RET_SUCCESS)


def _commit_changes(dracclient):
    # TODO(pas-ha) get job handle and verify result, return only when
    # job is done
    dracclient.create_config_job(
        CARD_SRV.uri,
        cim_creation_class_name=CARD_SRV_SELECT['CreationClassName'],
        cim_name=CARD_SRV_SELECT['Name'],
        target=iDRAC_FQDD)


class iDracVNCConsole(base.ConsoleInterface):
    """Control VNC server on Dell iDRAC >= 7 via WS-MAN API

    On starting console, sets VNC password, port, timeout and SSL settings
    from respective 'drac_vnc_*' driver_info fields.
    On get_console returns iDRAC host address and VNC port from driver info.

    """

    def get_properties(self):
        props = drac_common.COMMON_PROPERTIES.copy()
        props.udpate(DRAC_VNC_PROPERTIES)
        return props

    def validate(self, task):
        # TODO(pas-ha) validate license feature level
        p_info = drac_common.parse_driver_info(task.node)
        p_info.update(parse_vnc_driver_info(task.node))
        return p_info

    def start_console(self, task):
        p_info = parse_vnc_driver_info(task.node)
        client = drac_common.get_drac_client(task.node)
        # NOTE(pas-ha)
        # From many non-java vnc clients I've tested under Linux,
        # only xvnc4viewer seems to handle empty passwords.
        # With password set to not empty, most others work
        # but I could not make noVNC work :(
        _change_vnc_property(client,
                             'Password',
                             p_info['drac_vnc_password'])
        _change_vnc_property(client,
                             'SSLEncryptionBitLength',
                             p_info['drac_vnc_ssl_bitlength'])
        _change_vnc_property(client,
                             'Port',
                             str(p_info['drac_vnc_port']))
        _change_vnc_property(client,
                             'Timeout',
                             str(p_info['drac_vnc_timeout']))
        _change_vnc_property(client,
                             'Enable',
                             'Enabled')
        _commit_changes(client)

    def stop_console(self, task):
        client = drac_common.get_drac_client(task.node)
        _change_vnc_property(client, 'Enable', 'Disabled')
        _commit_changes(client)

    def get_console(self, task):
        p_info = parse_vnc_driver_info(task.node)
        p_info.update(drac_common.parse_driver_info(task.node))
        url = "vnc://{host}:{port}".format(host=p_info['drac_address'],
                                           port=p_info['drac_vnc_port'])
        return {'type': 'vnc', 'url': url}
