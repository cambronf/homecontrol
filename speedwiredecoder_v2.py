"""
 *
 * by david-m-m 2019-Mar-17
 * by datenschuft 2020-Jan-04
 *
 *  this software is released under GNU General Public License, version 2.
 *  This program is free software;
 *  you can redistribute it and/or modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; version 2 of the License.
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with this program;
 *  if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
"""

import binascii
from datetime import datetime

# unit definitions with scaling
sma_units = {
    "W": 10,
    "VA": 10,
    "VAr": 10,
    "kWh": 3600000,
    "kVAh": 3600000,
    "kVArh": 3600000,
    "A": 1000,
    "V": 1000,
    "°": 1000,
    "Hz": 1000,
}

# map of all defined SMA channels
# format: <channel_number>:(emparts_name>,<unit_actual>,<unit_total>)
sma_channels = {
    # totals
    1: ('pconsume', 'W', 'kWh'),
    2: ('psupply', 'W', 'kWh'),
    3: ('qconsume', 'VAr', 'kVArh'),
    4: ('qsupply', 'VAr', 'kVArh'),
    9: ('sconsume', 'VA', 'kVAh'),
    10: ('ssupply', 'VA', 'kVAh'),
    13: ('cosphi', '°'),
    14: ('frequency', 'Hz'),
    # phase 1
    21: ('p1consume', 'W', 'kWh'),
    22: ('p1supply', 'W', 'kWh'),
    23: ('q1consume', 'VAr', 'kVArh'),
    24: ('q1supply', 'VAr', 'kVArh'),
    29: ('s1consume', 'VA', 'kVAh'),
    30: ('s1supply', 'VA', 'kVAh'),
    31: ('i1', 'A'),
    32: ('u1', 'V'),
    33: ('cosphi1', '°'),
    # phase 2
    41: ('p2consume', 'W', 'kWh'),
    42: ('p2supply', 'W', 'kWh'),
    43: ('q2consume', 'VAr', 'kVArh'),
    44: ('q2supply', 'VAr', 'kVArh'),
    49: ('s2consume', 'VA', 'kVAh'),
    50: ('s2supply', 'VA', 'kVAh'),
    51: ('i2', 'A'),
    52: ('u2', 'V'),
    53: ('cosphi2', '°'),
    # phase 3
    61: ('p3consume', 'W', 'kWh'),
    62: ('p3supply', 'W', 'kWh'),
    63: ('q3consume', 'VAr', 'kVArh'),
    64: ('q3supply', 'VAr', 'kVArh'),
    69: ('s3consume', 'VA', 'kVAh'),
    70: ('s3supply', 'VA', 'kVAh'),
    71: ('i3', 'A'),
    72: ('u3', 'V'),
    73: ('cosphi3', '°'),
    # common
    36864: ('speedwire-version', ''),
}


def decode_obis(obis):
    measurement = int.from_bytes(obis[0:2], byteorder='big')
    raw_type = int.from_bytes(obis[2:3], byteorder='big')
    if raw_type == 4:
        datatype = 'actual'
    elif raw_type == 8:
        datatype = 'counter'
    elif raw_type == 0 and measurement == 36864:
        datatype = 'version'
    else:
        datatype = 'unknown'
        print('unknown datatype: measurement {} datatype {} raw_type {}'.format(measurement, datatype, raw_type))
    return measurement, datatype


def decode_speedwire(datagram):
    emparts = {}
    # process data only of SMA header is present
    if datagram[0:3] == b'SMA':
        # datagram length
        datalength = int.from_bytes(datagram[12:14], byteorder='big') + 16
        # print('data length: {}'.format(datalength))
        # serial number
        em_id = int.from_bytes(datagram[20:24], byteorder='big')
        # print('seral: {}'.format(em_id))
        emparts['serial'] = em_id
        # timestamp from SMA
        timestamp = int.from_bytes(datagram[24:28], byteorder='big')
        emparts['timestamp'] = timestamp
        # print('timestamp: {}'.format(timestamp))
        # date timestamp from system
        dt = datetime.now()
        emparts['datumtijd'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        # decode OBIS data blocks
        # start with header
        position = 28
        while position < datalength:
            # decode header
            # print('pos: {}'.format(position))
            (measurement, datatype) = decode_obis(datagram[position:position + 4])
            # print('measurement {} datatype: {}'.format(measurement,datatype))
            # decode values
            # actual values
            if datatype == 'actual':
                value = int.from_bytes(datagram[position + 4:position + 8], byteorder='big')
                position += 8
                if measurement in sma_channels.keys():
                    emparts[sma_channels[measurement][0]] = value / sma_units[sma_channels[measurement][1]]
                    emparts[sma_channels[measurement][0] + 'unit'] = sma_channels[measurement][1]
            # counter values
            elif datatype == 'counter':
                value = int.from_bytes(datagram[position + 4:position + 12], byteorder='big')
                position += 12
                if measurement in sma_channels.keys():
                    emparts[sma_channels[measurement][0] + 'counter'] = value / sma_units[sma_channels[measurement][2]]
                    # High Precision
                    emparts[sma_channels[measurement][0] + 'counterHP'] = value
                    emparts[sma_channels[measurement][0] + 'counterunit'] = sma_channels[measurement][2]
            elif datatype == 'version':
                value = datagram[position + 4:position + 8]
                if measurement in sma_channels.keys():
                    bversion = (binascii.b2a_hex(value).decode("utf-8"))
                    version = str(int(bversion[0:2], 16)) + "." + str(int(bversion[2:4], 16)) + "." + str(
                        int(bversion[4:6], 16))
                    revision = str(chr(int(bversion[6:8])))
                    # revision definitions
                    if revision == "1":
                        # S – Special Version
                        version = version + ".S"
                    elif revision == "2":
                        # A – Alpha (not yet Feature Complete, Version for verification and validation)
                        version = version + ".A"
                    elif revision == "3":
                        # B – Beta (Feature Complete, Version for verification and validation)
                        version = version + ".B"
                    elif revision == "4":
                        # R – Release Candidate
                        # Release (Version for verification, validation and field test / Release version)
                        version = version + ".R"
                    elif revision == "5":
                        # E – Experimental Version (local verification)
                        version = version + ".E"
                    elif revision == "6":
                        # N – No Revision
                        version = version + ".N"
                    # adding version number to compare versions
                    version = version + "|" + str(bversion[0:2]) + str(bversion[2:4]) + str(bversion[4:6])
                    emparts[sma_channels[measurement][0]] = version
                position += 8
            else:
                position += 8
    return emparts


def decode_speedwire_highres(datagram):
    empartshr = {}
    # process data only of SMA header is present
    if datagram[0:3] == b'SMA':
        # datagram length
        datalength = int.from_bytes(datagram[12:14], byteorder='big') + 16
        # print('data length: {}'.format(datalength))
        # decode OBIS data blocks

        position = 28
        while position < datalength:
            # decode header
            # print('pos: {}'.format(position))
            (measurement, datatype) = decode_obis(datagram[position:position + 4])
            # print('measurement {} datatype: {}'.format(measurement,datatype))
            # decode values
            if datatype == 'actual':
                position += 8
            elif datatype == 'counter':
                value = int.from_bytes(datagram[position + 4:position + 12], byteorder='big')
                position += 12
                if measurement in sma_channels.keys():
                    empartshr[sma_channels[measurement][0] + 'counter'] = value
            elif datatype == 'version':
                position += 8
            else:
                position += 8
    return empartshr