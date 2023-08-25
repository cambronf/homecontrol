#!/usr/bin/env python3
# coding=utf-8
# PEP8
"""
 *
 * by Frans Cambron
 * based on several scripts found on gitHub/internet
 * 
 * Original by Wenger Florian 2020-01-04
 * wenger@unifox.at
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

import signal
import logging
import sys
import argparse
import socket
import struct
import bisect
# import binascii
# import csv
import os
import time

import pymultimatic.api
import pysftp
import traceback
import requests
import configparser
import xmltodict
from xml.parsers.expat import ExpatError
import subprocess

from datetime import datetime
from datetime import date
import pytz

import asyncio
import aiohttp
import math
import shelve
# import csv
# import numpy as np

from speedwiredecoder_v2 import decode_speedwire

from csv import writer
from csv import DictWriter
from csv import DictReader
from pathlib import Path
from pyModbusTCP.client import ModbusClient

from pymultimatic.systemmanager import SystemManager
from pymultimatic.model import OperatingModes  # ,System, QuickVeto

from openhab import OpenHAB
# import mysql.connector

modbusWaittime = 0.1
dbShelve = '/mnt/sharedfolder/data/shelve.db'


# clean exit
def signal_handler(sig, frame):
    # Housekeeping -> nothing to clean up
    print('Signal handler called with signal:', sig, ', frame:', frame)
    print('CTRL + C = end program')
    sys.exit(0)


def append_list_as_row(file_name, list_of_elem):
    with open(file_name, 'a+', newline='') as write_obj:
        # Create a writer object from csv module
        csv_writer = writer(write_obj)
        # Add contents of list as last row in the csv file
        csv_writer.writerow(list_of_elem)


def append_dict_as_row(file_name, dict_of_elem, loc_field_names):
    with open(file_name, 'a+', newline='') as write_obj:
        # Create a writer object from csv module
        dict_writer = DictWriter(write_obj, fieldnames=loc_field_names)
        # Add dictionary as row in the csv
        dict_writer.writerow(dict_of_elem)


def sma_em_readmeter(select_em):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
    except OSError as sma_e:
        logger.error("Error creating socket: {0}".format(sma_e))
        sys.exit(1)

    source_address = ipnumbers[select_em]
    mcast_grp = mcastgrp[select_em]
    mcast_port = int(mcastport[select_em])

    try:
        xreq = struct.pack("=4sl4s", socket.inet_aton(mcast_grp), socket.INADDR_ANY, socket.inet_aton(source_address))
        # noinspection PyUnresolvedReferences
        sock.setsockopt(socket.SOL_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, xreq)
        sock.bind((mcast_grp, mcast_port))
    except OSError as sma_e:
        logger.error("Error binding socket: {0}".format(sma_e))
        sys.exit(1)

    # processing received messages
    try:
        smainfo = sock.recv(1024)
    except OSError as sma_e:
        logger.error("Error timeout receiving data: {0}".format(sma_e))
        sys.exit(1)

    sock.close()

    return decode_speedwire(smainfo)


def get_superglobal(key):
    d = shelve.open(dbShelve, flag='r')
    try:
        keyvalue = d.get(key)
    except KeyError:
        keyvalue = None
    finally:
        d.close()
    return keyvalue


def set_superglobal(key, value):
    d = shelve.open(dbShelve, flag='w')
    try:
        d[key] = value
    finally:
        d.close()
    return


def set_relay(relaynbr, new_status):
    relay_params = (
        ('Item', relaynbr),
        ('Action', 'Set'),
        ('Value', new_status),
    )
    try:
        req = requests.get(url, params=relay_params, timeout=5)
        req.raise_for_status()
    except requests.exceptions.RequestException as err:
        logger.error(err)


def get_status_relay(relaynbr):
    relay_params = (
        ('Item', relaynbr),
        ('Action', 'Get'),
    )
    try:
        req = requests.get(url, params=relay_params, timeout=5)
        req.raise_for_status()
        r = req.json()
        if "Status" in r:
            logger.debug("Get_status_relay " + relaynbr + " is " + r["Status"])
            return r["Status"]
        else:
            logger.debug("Get_status_relay " + relaynbr + " returns unknown status")
            return "UNKNOWN"
    except requests.exceptions.RequestException as err:
        logger.error(err)


def graycode(n):
    return n ^ (n >> 1)


def inversegraycode(n):
    inv = 0
    while n:
        inv = inv ^ n
        n >>= 1
    return inv


def get_ev_load():
    url_cbw = 'http://ipOfCBWunit/state.xml'
    response_cbw = requests.Response()
    try:
        response_cbw = requests.get(url_cbw)
    except requests.exceptions.RequestException as err:
        logger.error(err)

    logger.debug(response_cbw.text)
    data_cbw = {}
    try:
        data_cbw = xmltodict.parse(response_cbw.text, encoding="utf-8")
    except ExpatError:
        print("Failed to parse xml from response (%s)" % traceback.format_exc())

    code0 = 8 * int(data_cbw['datavalues']['relay1']) + 4 * int(data_cbw['datavalues']['relay2']) + \
        2 * int(data_cbw['datavalues']['relay3']) + int(data_cbw['datavalues']['relay4'])
    logger.debug(f"get_ev_load = {code0}")

    return code0


def set_ev_load(n):
    url_cbw = 'http://ipOfCBWunit/state.xml'
    response_cbw = requests.Response()
    try:
        response_cbw = requests.get(url_cbw)
    except requests.exceptions.RequestException as err:
        logger.error(err)

    logger.debug(f"set_ev_load previous code = {response_cbw.text}")

    data_cbw = {}
    try:
        data_cbw = xmltodict.parse(response_cbw.text, encoding="utf-8")
    except ExpatError:
        logger.error(f"Failed to parse xml from response {traceback.format_exc()}")

    code0 = 8 * int(data_cbw['datavalues']['relay1']) + 4 * int(data_cbw['datavalues']['relay2']) + \
        2 * int(data_cbw['datavalues']['relay3']) + int(data_cbw['datavalues']['relay4'])

    match n:
        case "+0" | "-0":   # don't change code
            code1 = code0

        case "+1":         # increase code by 1, to a maximum 15
            code1 = code0 + 1 if code0 < 15 else 15

        case "-1":          # decrease code by 1, to a minimum of 0
            code1 = code0 - 1 if code0 > 0 else 0

        case _:             # set code to fixed value
            try:
                code1 = int(n)
            except ValueError:
                code1 = 0
            # Reduce charging in slow steps
            # code1 = (code0 - 4) if code1 <= (code0 - 4) else code1
            code1 = code1 if 0 <= code1 <= 15 else 0

    logger.debug(f"set_ev_load code0 = {code0}, code1 = {code1}")

    relay1 = (code1 & 0x8) >> 3
    relay2 = (code1 & 0x4) >> 2
    relay3 = (code1 & 0x2) >> 1
    relay4 = code1 & 0x1

    url_cbw = 'http://ipOfCBWunit/state.xml?relay1=' + str(relay1) + '&relay2=' + str(relay2) + \
              '&relay3=' + str(relay3) + '&relay4=' + str(relay4)

    if code0 != code1:
        try:
            requests.get(url_cbw)
        except requests.exceptions.RequestException as err:
            logger.error(err)
        logger.debug(f"set_ev_load final result = {response.text}")


def set_cbw_reg2_remote(n):
    url_cbw = 'http://remoteIP/state.xml'
    response_cbw = requests.Response()
    try:
        response_cbw = requests.get(url_cbw)
    except requests.exceptions.RequestException as err:
        logger.error(err)

    logger.debug(f"current_cbw_reg2_remote = {response_cbw.text}")

    data_cbw = {}
    try:
        data_cbw = xmltodict.parse(response_cbw.text, encoding="utf-8")
    except ExpatError:
        logger.error(f"Failed to parse xml from response {traceback.format_exc()}")

    register2 = int(data_cbw['datavalues']['register2'])

    logger.debug(f"current_cbw_reg2_remote = {register2}")

    url_cbw = 'http://remoteIP/state.xml?register2=' + str(n)

    try:
        requests.get(url_cbw)
    except requests.exceptions.RequestException as err:
        logger.error(err)
    logger.debug(f"set_cbw_reg2_remote = {response.text}")


def time_in_range(start, end, current):
    """Returns whether current is in the range [start, end]"""
    return start <= current <= end


async def vaillant_daytemp(user, passw, zone, temp):
    async with aiohttp.ClientSession() as session:
        try:
            manager = SystemManager(user, passw, session)
            await manager.set_zone_heating_setpoint_temperature(zone, temp)
        except pymultimatic.api.ApiError as err:
            logger.error(err)


async def vaillant_op_mode(user, passw, zone, operation):
    async with aiohttp.ClientSession() as session:
        manager = SystemManager(user, passw, session)
        await manager.set_zone_heating_operating_mode(zone, operation)


async def vaillant_get_opmode(user, passw, zone):
    async with aiohttp.ClientSession() as session:
        try:
            manager = SystemManager(user, passw, session)
        except pymultimatic.api.ApiError as error:
            logger.error(f"ApiError: {error}")
            return error
        try:
            responses = await manager.get_zone(zone)
        except (pymultimatic.api.WrongResponseError, pymultimatic.api.ApiError, aiohttp.ClientConnectorError,
                aiohttp.ClientOSError) as error:
            logger.error(f"SomeError: {error}")
            return error
        try:
            logger.debug("vaillant_get_opmode from zone: " + zone)
            logger.debug(responses)
            return responses.heating.operating_mode.name
        except AttributeError as error:
            logger.error(f"AttributeError: {error}")
            return error


async def boiler_get_opmode(user, passw, zone):
    async with aiohttp.ClientSession() as session:
        try:
            manager = SystemManager(user, passw, session)
        except pymultimatic.api.ApiError as error:
            logger.error(f"ApiError: {error}")
            return error
        try:
            responses = await manager.get_hot_water(zone)
        except (pymultimatic.api.WrongResponseError, pymultimatic.api.ApiError, aiohttp.ClientConnectorError,
                aiohttp.ClientOSError) as error:
            logger.error(f"SomeError: {error}")
            return "OFF"
        try:
            logger.debug(responses)
            return responses.operating_mode.name
        except AttributeError as error:
            logger.error(f"AttributeError: {error}")
            return error


async def boiler_op_mode(user, passw, zone, operation):
    async with aiohttp.ClientSession() as session:
        try:
            manager = SystemManager(user, passw, session)
        except pymultimatic.api.ApiError as error:
            logger.error(error)
            return error
        try:
            await manager.set_hot_water_operating_mode(zone, operation)
        except (pymultimatic.api.WrongResponseError, pymultimatic.api.ApiError, aiohttp.ClientConnectorError) as error:
            logger.error(error)
            return error


def set_max_unloading_bat(max_discharge):
    logger.debug("Calling set_max_unloading_bat with max_discharge = " + str(max_discharge))

    mbc = ModbusClient()

    # uncomment this line to see debug message
    mbc.debug = True

    # define modbus server host, port
    mbc.host = SERVER_HOST_BAT
    mbc.port = SERVER_PORT_BAT
    mbc.unit_id = SERVER_UNIT_ID_BAT
    nul_parl = [0, 0, 0, 2500, 0, 0, 0, 0, 0, 0]

    # open or reconnect TCP to server
    if not mbc.is_open:
        if not mbc.open():
            logger.error(
                "**E** set_max_unloading_bat: unable to connect to " + SERVER_HOST_BAT + ":" + str(SERVER_PORT_BAT))

    # if open() is ok, write register (modbus function 0x03)
    if mbc.is_open:
        regsmbc = mbc.write_multiple_registers(40236, [0, 2424])
        logger.debug("**D** set_max_unloading_bat: write to 40236: " + str(regsmbc))

        nul_parl[7] = int(max_discharge)
        regsmbc = mbc.write_multiple_registers(40793, nul_parl)
        logger.debug("**D** set_max_unloading_bat: write to 40793: " + str(regsmbc))

    mbc.close()
    logger.debug(nul_parl)


def force_loading_bat(max_charge=2500):
    logger.debug(f"Calling force_loading_bat with max_charge = {max_charge}")

    mbc = ModbusClient()
    mbc.debug = True

    # define modbus server host, port
    mbc.host = SERVER_HOST_BAT
    mbc.port = SERVER_PORT_BAT
    mbc.unit_id = SERVER_UNIT_ID_BAT

    reg40793to40801 = [0, 0, 0, 2500, 0, 0, 0, 0, 0, 0]
    reg40149to40151 = [0x8000, 2500, 0, 802]
    reg41251 = [0, 2500]

    # open or reconnect TCP to server
    if not mbc.is_open:
        if not mbc.open():
            logger.error(f"**E** force_loading_bat: unable to connect to {SERVER_HOST_BAT}:{SERVER_PORT_BAT}")

    # if open() is ok, write register (modbus function 0x03)
    if mbc.is_open:
        regsmbc = mbc.write_multiple_registers(40236, [0, 2424])
        logger.debug(f"**D** force_loading_bat: write to 40236: {regsmbc}")
        time.sleep(modbusWaittime)

        reg40793to40801[3] = int(max_charge)
        regsmbc = mbc.write_multiple_registers(40793, reg40793to40801)
        logger.debug(f"**D** force_loading_bat: write to 40793: {regsmbc}")
        time.sleep(modbusWaittime)

        reg41251[1] = int(max_charge)
        regsmbc = mbc.write_multiple_registers(41251, reg41251)  # S32 FIX0
        logger.debug(f"**D** force_loading_bat: write to 41251: {regsmbc}")
        time.sleep(modbusWaittime)

        reg40149to40151[1] = int(max_charge)
        regsmbc = mbc.write_multiple_registers(40149, reg40149to40151)
        logger.debug(f"**D** force_loading_bat: write to 40149: {regsmbc}")

        set_superglobal('batLocked', max_charge)

    mbc.close()
    logger.debug(reg40793to40801)
    logger.debug(reg41251)
    logger.debug(reg40149to40151)


def release_bat():
    logger.debug("Calling release_bat")

    mbc = ModbusClient()
    mbc.debug = True

    # define modbus server host, port
    mbc.host = SERVER_HOST_BAT
    mbc.port = SERVER_PORT_BAT
    mbc.unit_id = SERVER_UNIT_ID_BAT
    nul_parl = [0, 0, 0, 2500, 0, 0, 0, 2500, 0, 0]

    # open or reconnect TCP to server
    if not mbc.is_open:
        if not mbc.open():
            logger.error(f"**E** force_loading_bat: unable to connect to {SERVER_HOST_BAT}:{SERVER_PORT_BAT}")

    # if open() is ok, write register (modbus function 0x03)
    if mbc.is_open:
        regsmbc = mbc.write_multiple_registers(40236, [0, 2424])
        logger.debug(f"**D** release_bat: write to 40236: {regsmbc}")

        regsmbc = mbc.write_multiple_registers(40793, nul_parl)
        logger.debug(f"**D** release_bat: write to 40793: {regsmbc}")
        time.sleep(modbusWaittime)

        regsmbc = mbc.write_multiple_registers(41251, [0, 2500])  # S32 FIX0
        logger.debug(f"**D** release_bat: write to 41251: {regsmbc}")
        time.sleep(modbusWaittime)

        regsmbc = mbc.write_multiple_registers(40149, [0, 2500, 0, 803])
        logger.debug(f"**D** release_bat: write to 40149: {regsmbc}")

        set_superglobal('batLocked', 0)

    mbc.close()
    logger.debug(nul_parl)


########################################################################################################################
# Setup logging to stdout and log file

parser = argparse.ArgumentParser()
parser.add_argument(
    "-l",
    "--log",
    default="info",
    help=(
        "Provide logging level. "
        "Example --log debug', default='info'")
)

options = parser.parse_args()
levels = {
    'critical': logging.CRITICAL,
    'error': logging.ERROR,
    'warning': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG
}

level = levels.get(options.log.lower())

if level is None:
    raise ValueError(
        f"log level given: {options.log}"
        f" -- must be one of: {' | '.join(levels.keys())}")

# Reset root-loggers
logging.root.handlers = []

logger = logging.getLogger()

# Loggers settings
logformat = logging.Formatter('[%(asctime)s], %(levelname)-8s, %(name)-12s, %(message)s', '%d-%m-%Y %H:%M:%S')

# Set default lowest log level
logger.setLevel(level)

# Setup stderr logger
stream_handler = logging.StreamHandler(stream=sys.stdout)
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(logformat)
logger.addHandler(stream_handler)

# Define extra handler and formatter for file logging
file_handler = logging.FileHandler(filename='/mnt/sharedfolder/home-log-' +
                                            str(date.today()) + '.log', encoding='utf-8', mode='a+')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logformat)
logger.addHandler(file_handler)

logger.debug(logger.handlers)

# for h in logger.handlers:
#    logging.debug(h.__dict__)

# Init Super Globals database, if necessary
if not os.path.isfile(dbShelve):
    db = shelve.open(dbShelve, flag='c')
    try:
        db['batLocked'] = 0
        db['evLoading'] = False
    finally:
        db.close()

db = shelve.open(dbShelve, flag='r')
logger.info(f"Start {__name__}, {list(db.items())}")
db.close()


########################################################################################################################
# abort-signal
signal.signal(signal.SIGINT, signal_handler)

if not hasattr(socket, 'IP_ADD_SOURCE_MEMBERSHIP'):
    setattr(socket, 'IP_ADD_SOURCE_MEMBERSHIP', 39)

# read configuration
path_current_directory = os.path.dirname(__file__)
path_config_file = os.path.join(path_current_directory, 'SMAconfig.ini')
# print (path_config_file)
parser = configparser.ConfigParser()

try:
    parser.read(path_config_file)
except configparser.ParsingError as e:
    logger.error('Error reading config file:\n' + str(e))

try:
    smaemserials = parser.get('SMA-EM', 'serials').split()
    ipnumbers = parser.get('SMA-EM', 'ipnumbers').split()
    mcastgrp = parser.get('SMA-EM', 'mcastgrp').split()
    mcastport = parser.get('SMA-EM', 'mcastport').split()

    myHostname = parser.get('FEATURE-upload', 'hostname')
    myUsername = parser.get('FEATURE-upload', 'username')
    myPassword = parser.get('FEATURE-upload', 'password')

    vaillantUsername = parser.get('Vaillant', 'username')
    vaillantPassword = parser.get('Vaillant', 'password')

    sql_host = parser.get('FEATURE-sql', 'sql_host')
    sql_user = parser.get('FEATURE-sql', 'sql_user')
    sql_password = parser.get('FEATURE-sql', 'sql_password')
    sql_database = parser.get('FEATURE-sql', 'sql_database')

    SERVER_HOST_PV = parser.get('SMA-PV', 'ipnumbers')
    SERVER_PORT_PV = int(parser.get('SMA-PV', 'serverport'))
    SERVER_UNIT_ID_PV = int(parser.get('SMA-PV', 'unit_id'))

    SERVER_HOST_PV2 = parser.get('SMA-PV2', 'ipnumbers')
    SERVER_PORT_PV2 = int(parser.get('SMA-PV2', 'serverport'))
    SERVER_UNIT_ID_PV2 = int(parser.get('SMA-PV2', 'unit_id'))

    SERVER_HOST_BAT = parser.get('SMA-BAT', 'ipnumbers')
    SERVER_PORT_BAT = int(parser.get('SMA-BAT', 'serverport'))
    SERVER_UNIT_ID_BAT = int(parser.get('SMA-BAT', 'unit_id'))

except configparser.NoOptionError as e:
    logger.error('Cannot parse config ./SMAconfig.ini')
    sys.exit(1)

########################################################################################################################
# SMA Mains metering SMA Homemanager
empartsMain = sma_em_readmeter(0)

########################################################################################################################
# SMA PV metering SMA Energymeter
empartsPV = sma_em_readmeter(1)

########################################################################################################################
# SMA Heatpump metering SMA Energymeter
empartsHP = sma_em_readmeter(2)

########################################################################################################################
# field names of CSV data
field_names = ['serial', 'datumtijd', 'timestamp',

               'pconsume', 'pconsumeunit', 'pconsumecounter', 'pconsumecounterunit',
               'psupply', 'psupplyunit', 'psupplycounter', 'psupplycounterunit',
               'qconsume', 'qconsumeunit', 'qconsumecounter', 'qconsumecounterunit',
               'qsupply', 'qsupplyunit', 'qsupplycounter', 'qsupplycounterunit',
               'sconsume', 'sconsumeunit', 'sconsumecounter', 'sconsumecounterunit',
               'ssupply', 'ssupplyunit', 'ssupplycounter', 'ssupplycounterunit',

               'cosphi', 'cosphiunit', 'frequency', 'frequencyunit',

               'p1consume', 'p1consumeunit', 'p1consumecounter', 'p1consumecounterunit',
               'p1supply', 'p1supplyunit', 'p1supplycounter', 'p1supplycounterunit',
               'q1consume', 'q1consumeunit', 'q1consumecounter', 'q1consumecounterunit',
               'q1supply', 'q1supplyunit', 'q1supplycounter', 'q1supplycounterunit',
               's1consume', 's1consumeunit', 's1consumecounter', 's1consumecounterunit',
               's1supply', 's1supplyunit', 's1supplycounter', 's1supplycounterunit',
               'i1', 'i1unit', 'u1', 'u1unit', 'cosphi1', 'cosphi1unit',

               'p2consume', 'p2consumeunit', 'p2consumecounter', 'p2consumecounterunit',
               'p2supply', 'p2supplyunit', 'p2supplycounter', 'p2supplycounterunit',
               'q2consume', 'q2consumeunit', 'q2consumecounter', 'q2consumecounterunit',
               'q2supply', 'q2supplyunit', 'q2supplycounter', 'q2supplycounterunit',
               's2consume', 's2consumeunit', 's2consumecounter', 's2consumecounterunit',
               's2supply', 's2supplyunit', 's2supplycounter', 's2supplycounterunit',
               'i2', 'i2unit', 'u2', 'u2unit', 'cosphi2', 'cosphi2unit',

               'p3consume', 'p3consumeunit', 'p3consumecounter', 'p3consumecounterunit',
               'p3supply', 'p3supplyunit', 'p3supplycounter', 'p3supplycounterunit',
               'q3consume', 'q3consumeunit', 'q3consumecounter', 'q3consumecounterunit',
               'q3supply', 'q3supplyunit', 'q3supplycounter', 'q3supplycounterunit',
               's3consume', 's3consumeunit', 's3consumecounter', 's3consumecounterunit',
               's3supply', 's3supplyunit', 's3supplycounter', 's3supplycounterunit',
               'i3', 'i3unit', 'u3', 'u3unit', 'cosphi3', 'cosphi3unit',

               'speedwire-version']

field_namesHP = ['serial', 'datumtijd', 'timestamp',

                 'pconsume', 'pconsumeunit', 'pconsumecounter', 'pconsumecounterHP', 'pconsumecounterunit',
                 'psupply', 'psupplyunit', 'psupplycounter', 'psupplycounterHP', 'psupplycounterunit',
                 'qconsume', 'qconsumeunit', 'qconsumecounter', 'qconsumecounterHP', 'qconsumecounterunit',
                 'qsupply', 'qsupplyunit', 'qsupplycounter', 'qsupplycounterHP', 'qsupplycounterunit',
                 'sconsume', 'sconsumeunit', 'sconsumecounter', 'sconsumecounterHP', 'sconsumecounterunit',
                 'ssupply', 'ssupplyunit', 'ssupplycounter', 'ssupplycounterHP', 'ssupplycounterunit',

                 'cosphi', 'cosphiunit', 'frequency', 'frequencyunit',

                 'p1consume', 'p1consumeunit', 'p1consumecounter', 'p1consumecounterHP', 'p1consumecounterunit',
                 'p1supply', 'p1supplyunit', 'p1supplycounter', 'p1supplycounterHP', 'p1supplycounterunit',
                 'q1consume', 'q1consumeunit', 'q1consumecounter', 'q1consumecounterHP', 'q1consumecounterunit',
                 'q1supply', 'q1supplyunit', 'q1supplycounter', 'q1supplycounterHP', 'q1supplycounterunit',
                 's1consume', 's1consumeunit', 's1consumecounter', 's1consumecounterHP', 's1consumecounterunit',
                 's1supply', 's1supplyunit', 's1supplycounter', 's1supplycounterHP', 's1supplycounterunit',
                 'i1', 'i1unit', 'u1', 'u1unit', 'cosphi1', 'cosphi1unit',

                 'p2consume', 'p2consumeunit', 'p2consumecounter', 'p2consumecounterHP', 'p2consumecounterunit',
                 'p2supply', 'p2supplyunit', 'p2supplycounter', 'p2supplycounterHP', 'p2supplycounterunit',
                 'q2consume', 'q2consumeunit', 'q2consumecounter', 'q2consumecounterHP', 'q2consumecounterunit',
                 'q2supply', 'q2supplyunit', 'q2supplycounter', 'q2supplycounterHP', 'q2supplycounterunit',
                 's2consume', 's2consumeunit', 's2consumecounter', 's2consumecounterHP', 's2consumecounterunit',
                 's2supply', 's2supplyunit', 's2supplycounter', 's2supplycounterHP', 's2supplycounterunit',
                 'i2', 'i2unit', 'u2', 'u2unit', 'cosphi2', 'cosphi2unit',

                 'p3consume', 'p3consumeunit', 'p3consumecounter', 'p3consumecounterHP', 'p3consumecounterunit',
                 'p3supply', 'p3supplyunit', 'p3supplycounter', 'p3supplycounterHP', 'p3supplycounterunit',
                 'q3consume', 'q3consumeunit', 'q3consumecounter', 'q3consumecounterHP', 'q3consumecounterunit',
                 'q3supply', 'q3supplyunit', 'q3supplycounter', 'q3supplycounterHP', 'q3supplycounterunit',
                 's3consume', 's3consumeunit', 's3consumecounter', 's3consumecounterHP', 's3consumecounterunit',
                 's3supply', 's3supplyunit', 's3supplycounter', 's3supplycounterHP', 's3supplycounterunit',
                 'i3', 'i3unit', 'u3', 'u3unit', 'cosphi3', 'cosphi3unit',

                 'speedwire-version']

field_namesSBF = ['datetime', 'DeviceName', 'DeviceType', 'Serial',
                  'Pdc1', 'Pdc2', 'Idc1', 'Idc2', 'Udc1', 'Udc2',
                  'Pac1', 'Pac2', 'Pac3', 'Iac1', 'Iac2', 'Iac3', 'Uac1', 'Uac2', 'Uac3',
                  'PdcTot', 'PacTot', 'Efficiency', 'EToday', 'ETotal', 'Frequency',
                  'OperatingTime', 'FeedInTime', 'BT_Signal', 'Condition', 'GridRelay', 'Temperature']

field_namesSBFbat = ['datetime', 'DeviceName', 'DeviceType', 'Serial',
                     'Pac1', 'Pac2', 'Pac3', 'Iac1', 'Iac2', 'Iac3', 'Uac1', 'Uac2', 'Uac3',
                     'PacTot', 'EToday', 'ETotal', 'Frequency',
                     'OperatingTime', 'FeedInTime', 'Condition',
                     'SOC', 'Tempbatt', 'Ubatt', 'Ibatt', 'TotWOut', 'TotWIn']

########################################################################################################################
# SMA PV metering from SMA Tri Power Inverter

filenameToday = '/mnt/sharedfolder/data/Log-Spot-' + date.today().strftime("%Y%m%d") + '.csv'
try:
    # -no csv flag -> enable CSV output (bug version 3.9.5 dd 8/6/2022)
    subprocess.run(["/usr/local/bin/sbfspot.3/SBFspot", "-nocsv", "-ae0", "-am0", "-ad0", "-finq"],
                   stdout=subprocess.DEVNULL, check=True, timeout=5)
except Exception as e:
    logger.error("Error getting data from SMA inverter, SBFspot exit code: ", e)

csv_dict = {}
if Path(filenameToday).is_file():
    # Open previous file in read mode
    with open(filenameToday, 'r', newline='') as read_obj:
        csv_dict_reader = DictReader(read_obj, fieldnames=field_namesSBF)
        csv_dict = list(csv_dict_reader)[-1]
        # print(csv_dict)

########################################################################################################################
# SMA PV metering from SMA Sunny Boy Inverter

filenameToday2 = '/mnt/sharedfolder/data/Log-Tuin-Spot-' + date.today().strftime("%Y%m%d") + '.csv'
try:
    # -no csv flag -> enable CSV output (bug version 3.9.5 dd 8/6/2022)
    subprocess.run(["/usr/local/bin/sbfspot.3/SBFspot", "-nocsv",
                    "-cfgSBFspotTuin.cfg", "-ae0", "-am0", "-ad0", "-finq"], stdout=subprocess.DEVNULL,
                   check=True, timeout=5)
except Exception as e:
    logger.error("Error getting data from SMA inverter, SBFspot exit code: ", e)

csv_dict2 = {}
if Path(filenameToday2).is_file():
    # Open previous file in read mode
    with open(filenameToday2, 'r', newline='') as read_obj:
        csv_dict_reader = DictReader(read_obj, fieldnames=field_namesSBF)
        csv_dict2 = list(csv_dict_reader)[-1]
        # print(csv_dict2)


# map data from SMA
# SMApartsInv = [None]*len(field_names)
SMApartsInv = dict.fromkeys(field_names, None)
SMApartsInv2 = dict.fromkeys(field_names, None)
# print(csv_dict)

SMApartsInv['serial'] = csv_dict.get('Serial')
SMApartsInv2['serial'] = csv_dict2.get('Serial')

SMApartsInv['datumtijd'] = SMApartsInv2['datumtijd'] = empartsMain['datumtijd']
SMApartsInv['timestamp'] = SMApartsInv2['timestamp'] = 0

# DC side power
SMApartsInv['pconsume'] = csv_dict.get('PdcTot')
SMApartsInv2['pconsume'] = csv_dict2.get('PdcTot')
SMApartsInv['pconsumeunit'] = SMApartsInv2['pconsumeunit'] = 'W'

SMApartsInv['p1consume'] = csv_dict.get('Pdc1')
SMApartsInv2['p1consume'] = csv_dict2.get('Pdc1')
SMApartsInv['p1consumeunit'] = SMApartsInv2['p1consumeunit'] = 'W'

SMApartsInv['p2consume'] = csv_dict.get('Pdc2')
SMApartsInv2['p2consume'] = csv_dict2.get('Pdc2')
SMApartsInv['p2consumeunit'] = SMApartsInv2['p2consumeunit'] = 'W'

SMApartsInv['p3consume'] = SMApartsInv2['p3consume'] = 0  # csv_dict.get('Pdc3')
SMApartsInv['p3consumeunit'] = SMApartsInv2['p3consumeunit'] = 'W'

# DC side currents
SMApartsInv['q1consume'] = csv_dict.get('Idc1')
SMApartsInv2['q1consume'] = csv_dict2.get('Idc1')
SMApartsInv['q1consumeunit'] = SMApartsInv2['q1consumeunit'] = 'A'

SMApartsInv['q2consume'] = csv_dict.get('Idc2')
SMApartsInv2['q2consume'] = csv_dict2.get('Idc2')
SMApartsInv['q2consumeunit'] = SMApartsInv2['q2consumeunit'] = 'A'

SMApartsInv['q3consume'] = SMApartsInv2['q3consume'] = 0  # csv_dict.get('Idc3')
SMApartsInv['q3consumeunit'] = SMApartsInv2['q3consumeunit'] = 'A'

# DC side voltages
SMApartsInv['s1consume'] = csv_dict.get('Udc1')
SMApartsInv2['s1consume'] = csv_dict2.get('Udc1')
SMApartsInv['s1consumeunit'] = SMApartsInv2['s1consumeunit'] = 'V'

SMApartsInv['s2consume'] = csv_dict.get('Udc2')
SMApartsInv2['s2consume'] = csv_dict2.get('Udc2')
SMApartsInv['s2consumeunit'] = SMApartsInv2['s2consumeunit'] = 'V'

SMApartsInv['s3consume'] = SMApartsInv2['s3consume'] = 0  # csv_dict.get('Udc3')
SMApartsInv['s3consumeunit'] = SMApartsInv2['s3consumeunit'] = 'V'

# AC side power
SMApartsInv['psupply'] = csv_dict.get('PacTot')
SMApartsInv2['psupply'] = csv_dict2.get('PacTot')
SMApartsInv['psupplyunit'] = SMApartsInv2['psupplyunit'] = 'W'

SMApartsInv['psupplycounter'] = csv_dict.get('ETotal')
SMApartsInv2['psupplycounter'] = csv_dict2.get('ETotal')
SMApartsInv['psupplycounterunit'] = SMApartsInv2['psupplycounterunit'] = 'kWh'

SMApartsInv['qsupplycounter'] = csv_dict.get('EToday')
SMApartsInv2['qsupplycounter'] = csv_dict2.get('EToday')
SMApartsInv['qsupplycounterunit'] = SMApartsInv2['qsupplycounterunit'] = 'kWh'

SMApartsInv['p1supply'] = csv_dict.get('Pac1')
SMApartsInv2['p1supply'] = csv_dict2.get('Pac1')
SMApartsInv['p1supplyunit'] = SMApartsInv2['p1supplyunit'] = 'W'

SMApartsInv['p2supply'] = csv_dict.get('Pac2')
SMApartsInv2['p2supply'] = csv_dict2.get('Pac2')
SMApartsInv['p2supplyunit'] = SMApartsInv2['p2supplyunit'] = 'W'

SMApartsInv['p3supply'] = csv_dict.get('Pac3')
SMApartsInv2['p3supply'] = csv_dict2.get('Pac3')
SMApartsInv['p3supplyunit'] = SMApartsInv2['p3supplyunit'] = 'W'

# AC side currents
SMApartsInv['i1'] = csv_dict.get('Iac1')
SMApartsInv2['i1'] = csv_dict2.get('Iac1')
SMApartsInv['i1unit'] = SMApartsInv2['i1unit'] = 'A'

SMApartsInv['i2'] = csv_dict.get('Iac2')
SMApartsInv2['i2'] = csv_dict2.get('Iac2')
SMApartsInv['i2unit'] = SMApartsInv2['i2unit'] = 'A'

SMApartsInv['i3'] = csv_dict.get('Iac3')
SMApartsInv2['i3'] = csv_dict2.get('Iac3')
SMApartsInv['i3unit'] = SMApartsInv2['i3unit'] = 'A'

# AC side voltages
SMApartsInv['u1'] = csv_dict.get('Uac1')
SMApartsInv2['u1'] = csv_dict2.get('Uac1')
SMApartsInv['u1unit'] = SMApartsInv2['u1unit'] = 'V'

SMApartsInv['u2'] = csv_dict.get('Uac2')
SMApartsInv2['u2'] = csv_dict2.get('Uac2')
SMApartsInv['u2unit'] = SMApartsInv2['u2unit'] = 'V'

SMApartsInv['u3'] = csv_dict.get('Uac3')
SMApartsInv2['u3'] = csv_dict2.get('Uac3')
SMApartsInv['u3unit'] = SMApartsInv2['u3unit'] = 'V'

# Extra info
SMApartsInv['cosphi'] = csv_dict.get('Efficiency')
SMApartsInv2['cosphi'] = csv_dict2.get('Efficiency')
SMApartsInv['cosphiunit'] = SMApartsInv2['cosphiunit'] = '%'

SMApartsInv['frequency'] = csv_dict.get('Frequency')
SMApartsInv2['frequency'] = csv_dict2.get('Frequency')
SMApartsInv['frequencyunit'] = SMApartsInv2['frequencyunit'] = 'Hz'

SMApartsInv2['pconsumecounter'] = 0
SMApartsInv2['pconsumecounterunit'] = 'x'
SMApartsInv2['qconsume'] = 0
SMApartsInv2['qconsumeunit'] = 'x'

SMApartsInv['qconsumecounter'] = SMApartsInv2['qconsumecounter'] = 0
SMApartsInv['qconsumecounterunit'] = SMApartsInv2['qconsumecounterunit'] = 'x'
SMApartsInv['qsupply'] = SMApartsInv2['qsupply'] = 0
SMApartsInv['qsupplyunit'] = SMApartsInv2['qsupplyunit'] = 'x'

SMApartsInv['sconsume'] = SMApartsInv2['sconsume'] = 0
SMApartsInv['sconsumeunit'] = SMApartsInv2['sconsumeunit'] = 'x'
SMApartsInv['sconsumecounter'] = SMApartsInv2['sconsumecounter'] = 0
SMApartsInv['sconsumecounterunit'] = SMApartsInv2['sconsumecounterunit'] = 'x'
SMApartsInv['ssupply'] = SMApartsInv2['ssupply'] = 0
SMApartsInv['ssupplyunit'] = SMApartsInv2['ssupplyunit'] = 'x'
SMApartsInv['ssupplycounter'] = SMApartsInv2['ssupplycounter'] = 0
SMApartsInv['ssupplycounterunit'] = SMApartsInv2['ssupplycounterunit'] = 'x'

SMApartsInv['p1consumecounter'] = SMApartsInv2['p1consumecounter'] = 0
SMApartsInv['p1consumecounterunit'] = SMApartsInv2['p1consumecounterunit'] = 'x'
SMApartsInv['p1supplycounter'] = SMApartsInv2['p1supplycounter'] = 0
SMApartsInv['p1supplycounterunit'] = SMApartsInv2['p1supplycounterunit'] = 'x'
SMApartsInv['q1consumecounter'] = SMApartsInv2['q1consumecounter'] = 0
SMApartsInv['q1consumecounterunit'] = SMApartsInv2['q1consumecounterunit'] = 'x'
SMApartsInv['q1supplycounter'] = SMApartsInv2['q1supplycounter'] = 0
SMApartsInv['q1supplycounterunit'] = SMApartsInv2['q1supplycounterunit'] = 'x'
SMApartsInv['q1supply'] = SMApartsInv2['q1supply'] = 0
SMApartsInv['q1supplyunit'] = SMApartsInv2['q1supplyunit'] = 'x'
SMApartsInv['q2supply'] = SMApartsInv2['q2supply'] = 0
SMApartsInv['q2supplyunit'] = SMApartsInv2['q2supplyunit'] = 'x'
SMApartsInv['s1consumecounter'] = SMApartsInv2['s1consumecounter'] = 0
SMApartsInv['s1consumecounterunit'] = SMApartsInv2['s1consumecounterunit'] = 'x'
SMApartsInv['s1supply'] = SMApartsInv2['s1supply'] = 0
SMApartsInv['s1supplyunit'] = SMApartsInv2['s1supplyunit'] = 'x'
SMApartsInv['s1supplycounter'] = SMApartsInv2['s1supplycounter'] = 0
SMApartsInv['s1supplycounterunit'] = SMApartsInv2['s1supplycounterunit'] = 'x'
SMApartsInv2['cosphi1'] = 0
SMApartsInv2['cosphi1unit'] = 'x'

SMApartsInv['p2consumecounter'] = SMApartsInv2['p2consumecounter'] = 0
SMApartsInv['p2consumecounterunit'] = SMApartsInv2['p2consumecounterunit'] = 'x'
SMApartsInv['p2supplycounter'] = SMApartsInv2['p2supplycounter'] = 0
SMApartsInv['p2supplycounterunit'] = SMApartsInv2['p2supplycounterunit'] = 'x'
SMApartsInv['q2consumecounter'] = SMApartsInv2['q2consumecounter'] = 0
SMApartsInv['q2consumecounterunit'] = SMApartsInv2['q2consumecounterunit'] = 'x'
SMApartsInv['q2supplycounter'] = SMApartsInv2['q2supplycounter'] = 0
SMApartsInv['q2supplycounterunit'] = SMApartsInv2['q2supplycounterunit'] = 'x'
SMApartsInv['s2consumecounter'] = SMApartsInv2['s2consumecounter'] = 0
SMApartsInv['s2consumecounterunit'] = SMApartsInv2['s2consumecounterunit'] = 'x'
SMApartsInv['s2supply'] = SMApartsInv2['s2supply'] = 0
SMApartsInv['s2supplyunit'] = SMApartsInv2['s2supplyunit'] = 'x'
SMApartsInv['s2supplycounter'] = SMApartsInv2['s2supplycounter'] = 0
SMApartsInv['s2supplycounterunit'] = SMApartsInv2['s2supplycounterunit'] = 'x'
SMApartsInv['cosphi2'] = SMApartsInv2['cosphi2'] = 0
SMApartsInv['cosphi2unit'] = SMApartsInv2['cosphi2unit'] = 'x'

SMApartsInv['p3consume'] = SMApartsInv2['p3consume'] = 0
SMApartsInv['p3consumeunit'] = SMApartsInv2['p3consumeunit'] = 'x'
SMApartsInv['p3consumecounter'] = SMApartsInv2['p3consumecounter'] = 0
SMApartsInv['p3consumecounterunit'] = SMApartsInv2['p3consumecounterunit'] = 'x'
SMApartsInv['p3supplycounter'] = SMApartsInv2['p3supplycounter'] = 0
SMApartsInv['p3supplycounterunit'] = SMApartsInv2['p3supplycounterunit'] = 'x'
SMApartsInv['q3consume'] = SMApartsInv2['q3consume'] = 0
SMApartsInv['q3consumeunit'] = SMApartsInv2['q3consumeunit'] = 'x'
SMApartsInv['q3consumecounter'] = SMApartsInv2['q3consumecounter'] = 0
SMApartsInv['q3consumecounterunit'] = SMApartsInv2['q3consumecounterunit'] = 'x'
SMApartsInv['q3supply'] = SMApartsInv2['q3supply'] = 0
SMApartsInv['q3supplyunit'] = SMApartsInv2['q3supplyunit'] = 'x'
SMApartsInv['q3supplycounter'] = SMApartsInv2['q3supplycounter'] = 0
SMApartsInv['q3supplycounterunit'] = SMApartsInv2['q3supplycounterunit'] = 'x'
SMApartsInv['s3consume'] = SMApartsInv2['s3consume'] = 0
SMApartsInv['s3consumeunit'] = SMApartsInv2['s3consumeunit'] = 'x'
SMApartsInv['s3consumecounter'] = SMApartsInv2['s3consumecounter'] = 0
SMApartsInv['s3consumecounterunit'] = SMApartsInv2['s3consumecounterunit'] = 'x'
SMApartsInv['s3supply'] = SMApartsInv2['s3supply'] = 0
SMApartsInv['s3supplyunit'] = SMApartsInv2['s3supplyunit'] = 'x'
SMApartsInv['s3supplycounter'] = SMApartsInv2['s3supplycounter'] = 0
SMApartsInv['s3supplycounterunit'] = SMApartsInv2['s3supplycounterunit'] = 'x'
SMApartsInv['cosphi3'] = SMApartsInv2['cosphi3'] = 0
SMApartsInv['cosphi3unit'] = SMApartsInv2['cosphi3unit'] = 'x'

SMApartsInv['speedwire-version'] = SMApartsInv2['speedwire-version'] = 'x'

# print(SMApartsInv)
# print(SMApartsInv2)

########################################################################################################################
# SMA Storage metering from SMA Battery Inverter

filenameToday = '/mnt/sharedfolder/data/Log-Battery-' + date.today().strftime("%Y%m%d") + '.csv'
try:
    # -no csv flag -> enable CSV output (bug version 3.9.5 dd 8/6/2022)
    subprocess.run(["/usr/local/bin/sbfspot.3/SBFspot", "-nocsv",
                    "-cfgSBFspotBat.cfg", "-ae0", "-am0", "-ad0", "-finq"], stdout=subprocess.DEVNULL,
                   check=True, timeout=5)
except Exception as e:
    print("Error getting data from SMA inverter, SBFspot exit code: ", e)

csv_dict = {}
if Path(filenameToday).is_file():
    # Open previous file in read mode
    with open(filenameToday, 'r', newline='') as read_obj:
        csv_dict_reader = DictReader(read_obj, fieldnames=field_namesSBFbat)
        csv_dict = list(csv_dict_reader)[-1]
#        print(csv_dict)
#        print(*csv_list, sep ="\n")

# map data from SMA
# SMApartsBat=[None]*len(field_names)
SMApartsBat = dict.fromkeys(field_names, None)
# print(csv_dict)

SMApartsBat['serial'] = csv_dict.get('Serial')

SMApartsBat['timestamp'] = 0
SMApartsBat['datumtijd'] = empartsMain['datumtijd']

# AC side power
if float(csv_dict['PacTot']) < 0:
    SMApartsBat['pconsume'] = -1.0 * float(csv_dict.get('PacTot'))
    SMApartsBat['psupply'] = 0.0
else:
    SMApartsBat['pconsume'] = 0.0
    SMApartsBat['psupply'] = float(csv_dict.get('PacTot'))
SMApartsBat['pconsumeunit'] = 'W'
SMApartsBat['psupplyunit'] = 'W'

if float(csv_dict['Pac1']) < 0:
    SMApartsBat['p1supply'] = 0.0
    SMApartsBat['p1consume'] = -1.0 * float(csv_dict.get('Pac1'))
else:
    SMApartsBat['p1consume'] = 0.0
    SMApartsBat['p1supply'] = float(csv_dict.get('Pac1'))
SMApartsBat['p1consumeunit'] = 'W'
SMApartsBat['p1supplyunit'] = 'W'

if float(csv_dict['Pac2']) < 0:
    SMApartsBat['p2supply'] = 0.0
    SMApartsBat['p2consume'] = -1.0 * float(csv_dict.get('Pac2'))
else:
    SMApartsBat['p2consume'] = 0.0
    SMApartsBat['p2supply'] = float(csv_dict.get('Pac2'))
SMApartsBat['p2consumeunit'] = 'W'
SMApartsBat['p2supplyunit'] = 'W'

if float(csv_dict['Pac3']) < 0:
    SMApartsBat['p3supply'] = 0.0
    SMApartsBat['p3consume'] = -1.0 * float(csv_dict.get('Pac3'))
else:
    SMApartsBat['p3consume'] = 0.0
    SMApartsBat['p3supply'] = float(csv_dict.get('Pac3'))
SMApartsBat['p3consumeunit'] = 'W'
SMApartsBat['p3supplyunit'] = 'W'

# DC side
SMApartsBat['q1consume'] = csv_dict.get('Ibatt')
SMApartsBat['q1consumeunit'] = 'A'
SMApartsBat['s1consume'] = csv_dict.get('Ubatt')
SMApartsBat['s1consumeunit'] = 'V'

SMApartsBat['q2consume'] = 0
SMApartsBat['q2consumeunit'] = 'x'
SMApartsBat['q3consume'] = 0
SMApartsBat['q3consumeunit'] = 'x'
SMApartsBat['s2consume'] = 0
SMApartsBat['s2consumeunit'] = 'x'
SMApartsBat['s3consume'] = 0
SMApartsBat['s3consumeunit'] = 'x'

SMApartsBat['psupplycounter'] = csv_dict.get('ETotal')
SMApartsBat['psupplycounterunit'] = 'kWh'

SMApartsBat['pconsumecounter'] = 0
SMApartsBat['pconsumecounterunit'] = 'kWh'

# AC side currents
SMApartsBat['i1'] = csv_dict.get('Iac1')
SMApartsBat['i1unit'] = 'A'
SMApartsBat['i2'] = csv_dict.get('Iac2')
SMApartsBat['i2unit'] = 'A'
SMApartsBat['i3'] = csv_dict.get('Iac3')
SMApartsBat['i3unit'] = 'A'
# AC side voltages
SMApartsBat['u1'] = csv_dict.get('Uac1')
SMApartsBat['u1unit'] = 'V'
SMApartsBat['u2'] = csv_dict.get('Uac2')
SMApartsBat['u2unit'] = 'V'
SMApartsBat['u3'] = csv_dict.get('Uac3')
SMApartsBat['u3unit'] = 'V'

# Extra info
SMApartsBat['cosphi'] = csv_dict.get('SOC')
SMApartsBat['cosphiunit'] = '%'
SMApartsBat['frequency'] = csv_dict.get('Frequency')
SMApartsBat['frequencyunit'] = 'Hz'

SMApartsBat['qconsume'] = 0
SMApartsBat['qconsumeunit'] = 'x'
SMApartsBat['qconsumecounter'] = 0
SMApartsBat['qconsumecounterunit'] = 'x'
SMApartsBat['qsupply'] = 0
SMApartsBat['qsupplyunit'] = 'x'
SMApartsBat['qsupplycounter'] = 0
SMApartsBat['qsupplycounterunit'] = 'x'
SMApartsBat['sconsume'] = 0
SMApartsBat['sconsumeunit'] = 'x'
SMApartsBat['sconsumecounter'] = 0
SMApartsBat['sconsumecounterunit'] = 'x'
SMApartsBat['ssupply'] = 0
SMApartsBat['ssupplyunit'] = 'x'
SMApartsBat['ssupplycounter'] = 0
SMApartsBat['ssupplycounterunit'] = 'x'
SMApartsBat['p1consumecounter'] = 0
SMApartsBat['p1consumecounterunit'] = 'x'
SMApartsBat['p1supplycounter'] = 0
SMApartsBat['p1supplycounterunit'] = 'x'
SMApartsBat['q1consumecounter'] = 0
SMApartsBat['q1consumecounterunit'] = 'x'
SMApartsBat['q1supplycounter'] = 0
SMApartsBat['q1supplycounterunit'] = 'x'
SMApartsBat['q1supply'] = 0
SMApartsBat['q1supplyunit'] = 'x'
SMApartsBat['q2supply'] = 0
SMApartsBat['q2supplyunit'] = 'x'
SMApartsBat['s1consumecounter'] = 0
SMApartsBat['s1consumecounterunit'] = 'x'
SMApartsBat['s1supply'] = 0
SMApartsBat['s1supplyunit'] = 'x'
SMApartsBat['s1supplycounter'] = 0
SMApartsBat['s1supplycounterunit'] = 'x'
SMApartsBat['cosphi1'] = 0
SMApartsBat['cosphi1unit'] = 'x'
SMApartsBat['p2consumecounter'] = 0
SMApartsBat['p2consumecounterunit'] = 'x'
SMApartsBat['p2supplycounter'] = 0
SMApartsBat['p2supplycounterunit'] = 'x'
SMApartsBat['q2consumecounter'] = 0
SMApartsBat['q2consumecounterunit'] = 'x'
SMApartsBat['q2supplycounter'] = 0
SMApartsBat['q2supplycounterunit'] = 'x'
SMApartsBat['s2consumecounter'] = 0
SMApartsBat['s2consumecounterunit'] = 'x'
SMApartsBat['s2supply'] = 0
SMApartsBat['s2supplyunit'] = 'x'
SMApartsBat['s2supplycounter'] = 0
SMApartsBat['s2supplycounterunit'] = 'x'
SMApartsBat['cosphi2'] = 0
SMApartsBat['cosphi2unit'] = 'x'
SMApartsBat['p3consume'] = 0
SMApartsBat['p3consumeunit'] = 'x'
SMApartsBat['p3consumecounter'] = 0
SMApartsBat['p3consumecounterunit'] = 'x'
SMApartsBat['p3supplycounter'] = 0
SMApartsBat['p3supplycounterunit'] = 'x'
SMApartsBat['q3consume'] = 0
SMApartsBat['q3consumeunit'] = 'x'
SMApartsBat['q3consumecounter'] = 0
SMApartsBat['q3consumecounterunit'] = 'x'
SMApartsBat['q3supply'] = 0
SMApartsBat['q3supplyunit'] = 'x'
SMApartsBat['q3supplycounter'] = 0
SMApartsBat['q3supplycounterunit'] = 'x'
SMApartsBat['s3consume'] = 0
SMApartsBat['s3consumeunit'] = 'x'
SMApartsBat['s3consumecounter'] = 0
SMApartsBat['s3consumecounterunit'] = 'x'
SMApartsBat['s3supply'] = 0
SMApartsBat['s3supplyunit'] = 'x'
SMApartsBat['s3supplycounter'] = 0
SMApartsBat['s3supplycounterunit'] = 'x'
SMApartsBat['cosphi3'] = 0
SMApartsBat['cosphi3unit'] = 'x'
SMApartsBat['speedwire-version'] = 'x'
# print(SMApartsBat)

########################################################################################################################
# data_types = ['#datatype tag','dateTime:RFC3339','string','string','unsignedLong','double','string','double',
# 'string','double','string','double','string','double','string','double','string','double','string','double','string',
# 'double','string','double','string','double','string','double','string','double','string','double','string','double',
# 'string','double','string','double','string','double','string','double','string','double','string','double','string',
# 'double','string','double','string','double','string','double','string','double','string','double','string','double',
# 'string','double','string','double','string','double','string','double','string','double','string','double','string',
# 'double','string','double','string','double','string','double','string','double','string','double','string','double',
# 'string','double','string','double','string','double','string','double','string','double','string','double','string',
# 'double','string','double','string','double','string','double','string','double','string','double','string','double',
# 'string','double','string','double','string','double','string','double','string','double','string','string']
# defaults = ['#default ','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
# '50','Hz','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
# '','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
# '','','','','','','','','','','','','','','','','','']
empartsPV['frequency'] = 50.0
empartsPV['frequencyunit'] = 'Hz'
empartsHP['frequency'] = 50.0
empartsHP['frequencyunit'] = 'Hz'

# field_names_header = [ 'serial', 'datumtijd:RFC3339' ]

# Use same time for all meters
empartsPV['datumtijd'] = empartsMain['datumtijd']
empartsHP['datumtijd'] = empartsMain['datumtijd']

# Local log file (inc high precision counter values)
filename = '/mnt/sharedfolder/data/smalog_HP_' + empartsMain['datumtijd'][0:10] + '.csv'
# print(filename)
if not Path(filename).is_file():
    append_list_as_row(filename, field_namesHP)

append_dict_as_row(filename, empartsMain, field_namesHP)
append_dict_as_row(filename, empartsPV, field_namesHP)
append_dict_as_row(filename, empartsHP, field_namesHP)

# replace sampled power measurements by averaged values: delta(energy)/delta(time)
filenameNt0 = '/mnt/sharedfolder/data/todayV1.csv'
filenameNt1 = '/mnt/sharedfolder/data/todayV1-1.csv'
filenameNt2 = '/mnt/sharedfolder/data/todayV1-2.csv'
filenameNt3 = '/mnt/sharedfolder/data/todayV1-3.csv'
filenameNt4 = '/mnt/sharedfolder/data/todayV1-4.csv'
filenameUpload = '/mnt/sharedfolder/data/todayUpload.csv'

if Path(filenameUpload).is_file():
    os.remove(filenameUpload)

empartsMainN1 = [None] * len(field_namesHP)
empartsPVN1 = [None] * len(field_namesHP)
empartsHPN1 = [None] * len(field_namesHP)

if Path(filenameNt3).is_file():
    os.rename(filenameNt3, filenameNt4)
if Path(filenameNt2).is_file():
    os.rename(filenameNt2, filenameNt3)
if Path(filenameNt1).is_file():
    os.rename(filenameNt1, filenameNt2)
if Path(filenameNt0).is_file():
    os.rename(filenameNt0, filenameNt1)

append_dict_as_row(filenameNt0, empartsMain, field_namesHP)
append_dict_as_row(filenameNt0, empartsPV, field_namesHP)
append_dict_as_row(filenameNt0, empartsHP, field_namesHP)

# Average values over one minute
if Path(filenameNt1).is_file():
    # Open previous file in read mode
    with open(filenameNt1, 'r', newline='') as read_obj:
        csv_dict_reader = DictReader(read_obj, fieldnames=field_namesHP)

        csv_list = list(csv_dict_reader)
        empartsMainN1 = csv_list[0]
        empartsPVN1 = csv_list[1]
        empartsHPN1 = csv_list[2]

        # 3600 seconds/hour * 1000 (for kWh -> Ws), *1000 as timestamps are in milliseconds
        deltaTimeMain = int(empartsMain['timestamp']) - int(empartsMainN1.get('timestamp'))
        deltaTimePV = int(empartsPV['timestamp']) - int(empartsPVN1.get('timestamp'))
        deltaTimeHP = int(empartsHP['timestamp']) - int(empartsHPN1.get('timestamp'))

        empartsMain['pconsume'] = \
            1000.0 * \
            ((int(empartsMain['pconsumecounterHP']) - int(empartsMainN1.get('pconsumecounterHP'))) / deltaTimeMain)
        empartsMain['psupply'] = \
            1000.0 * \
            ((int(empartsMain['psupplycounterHP']) - int(empartsMainN1.get('psupplycounterHP'))) / deltaTimeMain)

        empartsPV['pconsume'] = \
            1000.0 * ((int(empartsPV['pconsumecounterHP']) - int(empartsPVN1.get('pconsumecounterHP'))) / deltaTimePV)
        empartsPV['psupply'] = \
            1000.0 * ((int(empartsPV['psupplycounterHP']) - int(empartsPVN1.get('psupplycounterHP'))) / deltaTimePV)

        empartsHP['pconsume'] = \
            1000.0 * ((int(empartsHP['pconsumecounterHP']) - int(empartsHPN1.get('pconsumecounterHP'))) / deltaTimeHP)
        empartsHP['psupply'] = \
            1000.0 * ((int(empartsHP['psupplycounterHP']) - int(empartsHPN1.get('psupplycounterHP'))) / deltaTimeHP)

# Average values over 5 minutes
empartsMainN4 = [None] * len(field_namesHP)
empartsHPN4 = [None] * len(field_namesHP)
ElecNetAvg = ElecHPAvg = 0.0

if Path(filenameNt4).is_file():
    # Open previous file in read mode
    with open(filenameNt4, 'r', newline='') as read_obj:
        csv_dict_reader = DictReader(read_obj, fieldnames=field_namesHP)

        csv_list = list(csv_dict_reader)
        empartsMainN4 = csv_list[0]
        empartsHPN4 = csv_list[2]

        # 3600 seconds/hour * 1000 (for kWh -> Ws), *1000 as timestamps are in milliseconds
        deltaTimeMain = int(empartsMain['timestamp']) - int(empartsMainN4.get('timestamp'))
        deltaTimeHP = int(empartsHP['timestamp']) - int(empartsHPN4.get('timestamp'))

        ElecNetAvg = 1000.0 * \
            ((int(empartsMain['pconsumecounterHP']) - int(empartsMainN4.get('pconsumecounterHP'))) / deltaTimeMain)

        ElecHPAvg = \
            1000.0 * ((int(empartsHP['pconsumecounterHP']) - int(empartsHPN4.get('pconsumecounterHP'))) / deltaTimeHP)


# Velbus LED control
# Producenten:
netP = empartsMain['pconsume'] - empartsMain['psupply']
sunP = float(SMApartsInv['psupply']) + float(SMApartsInv2['psupply'])
batP = SMApartsBat['psupply'] - SMApartsBat['pconsume']
# Verbruikers
heatP = empartsHP['pconsume']
houseP = netP + sunP + batP - heatP
# Battery status
batSoC = float(SMApartsBat['cosphi'])

url = 'http://openhabServer/velserver/service.pl'

headers = {
    'Content-Type': 'text/html',
}

params = (
    ('Item', 'Memo_73_98'),
    ('Action', 'Set'),
)

# data = 'N:' + str(round(netP)) + ' S:' + str(round(sunP)) + ' B:' + str(round(batP)) + ' V:' + str(round(houseP)) +
# ' W:' + str(round(heatP)) + ' Soc:' + str(round(batSoC)) + '%'
data = 'N:' + str(round(netP)) + ' S:' + str(round(sunP)) + ' B:' + str(round(batP)) + ' C:' + str(round(batSoC))
print(data)
response = requests.post(url, headers=headers, params=params, data=data)

# params = (
#    ('Item', 'ELEdgeLeft_73_97'),
#    ('Action', 'Set'),
# )

# data = '173023654'
# response = requests.post('http://openhabServer/velserver/service.pl', headers=headers, params=params, data=data)

# read tariff plan from openHAB environment
base_url = 'http://openhabServer:8080/rest'
openhab = OpenHAB(base_url)

# get some items from openhab
itemRestVandaag = openhab.get_item('PVRestVandaag')
itemPVMorgen = openhab.get_item('PVMorgen')

itemEVPower = openhab.get_item('Auto_Power')
itemEVPower15m = openhab.get_item('ElektriciteitEvAvg15m')

itemcp = openhab.get_item('ElecCostPeriod')
itemcpNextHour = openhab.get_item('ElecCostNextHour')
# get battery load power
BatLoadPower = SMApartsBat['pconsume']

# store PV Energy of today
itemPV = openhab.get_item('PVVandaag')
itemPV.state = float(SMApartsInv['qsupplycounter']) + float(SMApartsInv2['qsupplycounter'])
# store Bat SoC
itemBYD = openhab.get_item('BYDbatterySOC')
itemBYD.state = batSoC
# store 5 minutes average values of net and heatpump consumption
itemElecAvg = openhab.get_item('ElektriciteitAfnAvg')
itemElecAvg.state = ElecNetAvg
itemHPAvg = openhab.get_item('ElektriciteitWpAvg')
itemHPAvg.state = ElecHPAvg
# get 15 minutes average values of net and heatpump consumption
itemElecAvg15m = openhab.get_item('ElektriciteitAfnAvg15m')
itemHPAvg15m = openhab.get_item('ElektriciteitWpAvg15m')

# get sunrise time
itemDayLightStartTime = openhab.get_item("Astro_Sun_Data_Start_Time")
itemDayLightEndTime = openhab.get_item("Astro_Sun_Data_End_Time")
# delta seconds today's sunrise/sunset
localTz = pytz.timezone('Europe/Brussels')
nextSunriseSeconds = (itemDayLightStartTime.state - datetime.now(localTz)).total_seconds()
nextSunsetSeconds = (itemDayLightEndTime.state - datetime.now(localTz)).total_seconds()

batTarget = 0.0
if (nextSunriseSeconds > 0) and (nextSunsetSeconds > 0):
    pvAvailable = itemRestVandaag.state if itemRestVandaag.state > 0.0 else itemPVMorgen.state
    batTarget = max(0.0, 10.0 * (max(0.0, 7.0 - pvAvailable/2.5) + nextSunriseSeconds/7200.0))
elif (nextSunriseSeconds < 0) and (nextSunsetSeconds > 0):
    pvAvailable = itemRestVandaag.state
    batTarget = max(0.0, 10.0 * (7.0 - pvAvailable/2.5))
elif (nextSunriseSeconds < 0) and (nextSunsetSeconds < 0):
    pvAvailable = itemPVMorgen.state
    batTarget = min(100.0, max(0.0, 10.0 * (max(0.0, 7.0 - pvAvailable/2.5) + (86400 + nextSunriseSeconds)/7200.0)))

itemBYDtar = openhab.get_item('BYDbatteryTarget')
itemBYDtar.state = batTarget

if not itemcp.is_state_null():
    if math.floor(itemcp.state) == 0:
        params = (('Item', 'Button_45_03'), ('Action', 'Set'), ('Value', 'ON'))  # green
    elif math.floor(itemcp.state) == 1:
        params = (('Item', 'Button_45_04'), ('Action', 'Set'), ('Value', 'ON'))  # white
    elif math.floor(itemcp.state) == 2:
        params = (('Item', 'Button_45_05'), ('Action', 'Set'), ('Value', 'ON'))  # blue
    elif math.floor(itemcp.state) == 3:
        params = (('Item', 'Button_45_06'), ('Action', 'Set'), ('Value', 'ON'))  # red
    logger.debug(params)
    response = requests.get(url, params=params)

if float(SMApartsInv['psupplycounter']) > 0:
    itemsunenergy = openhab.get_item('SunInvertorEnergy')
    itemsunenergy.state = float(SMApartsInv['psupplycounter']) + float(SMApartsInv2['psupplycounter'])


########################################################################################################################
# Energy management
maxPiekVermogen = [5500, 5500, 4500, 4000, 3000, 3000, 3000, 3000, 3000, 4000, 4500, 5500]  # Max per month
EVVermogen = [0, 1459, 1663, 1845, 2048, 2252, 2452, 2607, 2833, 3030, 3232, 3400, 3600, 3636, 3640, 4200]
HPboON = HPbeON = HPwwON = False
EVON = False
BatON = False
allowDischarge = False

# select 2 minute time interval * 5 slots (minutes = 1, 3, 5, 7, 9)
minuut = 60 * (datetime.now().hour % 2) + datetime.now().minute
timeslot = 4 if minuut % 2 == 0 else (minuut // 2) % 4

tarief = itemcp.state
# Get release time for EV charging
# if openhab.get_item('autoChargeRelease').state is None:
if openhab.get_item('autoChargeRelease').is_state_null():
    EVchargeTime = datetime(1, 1, 1, 0, 0, 0)
else:
    EVchargeTime = openhab.get_item('autoChargeRelease').state.replace(tzinfo=None)
datenow = datetime.now().replace(second=0, microsecond=0)

# EV loading start (+/- 1min around EV charge release time)
if abs(datenow - EVchargeTime).seconds < 90:
    set_superglobal('evLoading', True)

# release EV loading minimum 10 min after EV charge release time, and EV charging power is below 100W
if ((datenow - EVchargeTime).seconds > 600) and (itemEVPower.state < 100) and (itemEVPower15m.state < 100):
    set_superglobal('evLoading', False)

if get_superglobal('evLoading'):
    EVON = True
else:
    # Heatpump only active when no EV charging
    if tarief < 1.9:
        HPbeON = True
    if tarief < 0.9:
        HPboON = True
    if tarief < 0.6:
        HPwwON = True

if tarief < 1.0:
    BatON = True

# available power for EV or Battery
maxPeakPowerThisMonth = maxPiekVermogen[date.today().month - 1]
availablePowerEV = 2500 if 8 < datenow.hour < 22 else int(min(4200, maxPeakPowerThisMonth - 500))
availablePowerBat = int(min(2500, max(0, maxPeakPowerThisMonth - (ElecNetAvg - BatLoadPower) - 500)))

if ElecNetAvg > maxPeakPowerThisMonth:
    if BatLoadPower > 400.0:
        timeslot = 4
    elif ElecHPAvg > 1000.0:
        HPboON = HPbeON = HPwwON = False
        timeslot = 12
    else:
        allowDischarge = True
        timeslot = 4

# Control Heatpump
beneden = "Control_ZO2"
boven = "Control_ZO1"
boiler = "Control_DHW"
WarmWaterONrelay = 'Relay_13_05'
event_loop = None

if (timeslot <= 2) or (timeslot == 12):
    try:
        event_loop = asyncio.get_running_loop()
    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

# get current status WP beneden:
opMode0 = ""
if (timeslot == 0) or (timeslot == 12):
    opMode0 = event_loop.run_until_complete(vaillant_get_opmode(vaillantUsername, vaillantPassword, beneden))

    if opMode0 != 'OFF':
        if HPbeON:
            if opMode0 == 'NIGHT':
                event_loop.run_until_complete(
                    vaillant_op_mode(vaillantUsername, vaillantPassword, beneden, OperatingModes.DAY))
        elif opMode0 == 'DAY':
            event_loop.run_until_complete(
                vaillant_op_mode(vaillantUsername, vaillantPassword, beneden, OperatingModes.NIGHT))

# get current status WP boven:
opMode1 = ""
if (timeslot == 1) or (timeslot == 12):
    opMode1 = event_loop.run_until_complete(vaillant_get_opmode(vaillantUsername, vaillantPassword, boven))

    if opMode1 != 'OFF':
        if HPboON:
            if opMode1 == 'NIGHT':
                event_loop.run_until_complete(
                    vaillant_op_mode(vaillantUsername, vaillantPassword, boven, OperatingModes.DAY))
        elif opMode1 == 'DAY':
            event_loop.run_until_complete(
                vaillant_op_mode(vaillantUsername, vaillantPassword, boven, OperatingModes.NIGHT))

# get current status heating water
opMode2 = ""
if (timeslot == 2) or (timeslot == 12):
    opMode2 = event_loop.run_until_complete(boiler_get_opmode(vaillantUsername, vaillantPassword, boiler))

    if get_status_relay(WarmWaterONrelay) == 'ON':
        if HPwwON:
            if opMode2 == 'OFF':
                event_loop.run_until_complete(
                    boiler_op_mode(vaillantUsername, vaillantPassword, boiler, OperatingModes.ON))
        elif opMode2 == 'ON':
            event_loop.run_until_complete(
                boiler_op_mode(vaillantUsername, vaillantPassword, boiler, OperatingModes.OFF))

if (timeslot <= 2) or (timeslot == 12):
    event_loop.close()

# Control EV auto loading
progLaden = 'Relay_1A_05'
AutoONrelay = 'Relay_1A_03'
# find max EV power that can be used for loading:
iMax = str(bisect.bisect(EVVermogen, availablePowerEV) - 1)

if timeslot == 3:
    if get_status_relay(progLaden) == 'ON':
        if EVON:
            set_ev_load(iMax)
            set_relay(AutoONrelay, 'ON')
        else:
            set_ev_load("0")
            set_relay(AutoONrelay, 'OFF')
    else:
        if get_status_relay(AutoONrelay) == 'ON':
            if get_ev_load() == 0:
                set_ev_load(iMax)
                set_relay(AutoONrelay, 'ON')
        else:
            set_ev_load("0")
            set_relay(AutoONrelay, 'OFF')

# Control Battery charging/discharging
maxDischarge = 2500
histBat = 7
loadBat = False
# Limit battery discharge if (heating pump is operational) or (EV is charging) or (low tariff period 0 or 1)
# to 0W if SoC is below target, else to 2500W
if (ElecHPAvg > 1000.0) or (itemEVPower.state > 1000.0):
    if batSoC - histBat < batTarget:
        maxDischarge = 0
    else:
        maxDischarge = 2500
if math.floor(itemcp.state) <= 1:
    if batSoC - histBat < batTarget:
        maxDischarge = 0
    else:
        maxDischarge = 500 + 20 * max(0.0, batSoC - histBat - batTarget)

if allowDischarge:
    maxDischarge = 2500

if timeslot == 4:
    batLocked = False if (get_superglobal('batLocked') is None) or (get_superglobal('batLocked') == 0) else True

    # Add 7.0% to avoid fast charge/discharge oscillations
    if (BatON and (availablePowerBat > 500)) and (tarief < itemcpNextHour.state) and \
            (batSoC < batTarget + (histBat if batLocked else 0.0)):
        loadBat = True

    # Bat loading stops automatically after 30min loading.
    # Bat release necessary to allow further control
    if batLocked and (int(BatLoadPower) == 0):
        release_bat()

    if loadBat:
        if get_superglobal('batLocked') != availablePowerBat:
            release_bat()
            force_loading_bat(availablePowerBat)
    else:
        if batLocked:
            release_bat()
        set_max_unloading_bat(maxDischarge)


logString = f"**Optim**, TS: {timeslot}, Max Peak: {maxPeakPowerThisMonth}W, " \
            f"Net usage last 5m: {ElecNetAvg:.1f}W, Tariff status: {itemcp.state:.2f}, "

match timeslot:
    case 0 | 12:
        logString2 = \
            f"Max P HPload: {maxPeakPowerThisMonth}W, HPbeON: {HPbeON}, status: {opMode0}, Warmtepomp: {ElecHPAvg:.1f}W"
    case 1 | 12:
        logString2 = \
            f"Max P HPload: {maxPeakPowerThisMonth}W, HPboON: {HPboON}, status: {opMode1}, Warmtepomp: {ElecHPAvg:.1f}W"
    case 2 | 12:
        logString2 = \
            f"Max P HPload: {maxPeakPowerThisMonth}W, HPwwON: {HPwwON}, status: {opMode2}, Warmtepomp: {ElecHPAvg:.1f}W"
    case 3:
        logString2 = \
            f"Max P EVload: {availablePowerEV}W, EVON: {EVON}, code: {int(iMax)}, EVpower: {itemEVPower.state:.1f}W"
    case 4 | 34:
        logString2 = \
            f"Max P Batload: {availablePowerBat}W, BatON: {BatON}, locked: {get_superglobal('batLocked')}, " \
            f"Batpower: {BatLoadPower:.1f}W, Battery SoC: {batSoC:.1f}%, " \
            f"target load: {batTarget:.2f}%, max discharge: {maxDischarge}W, loadBat: {loadBat}"
    case _:
        logString2 = ", invalid timeslot"

logger.info(f"{logString}{logString2}")

if (netP < -1800.0) and (tarief < 1.50):
    set_cbw_reg2_remote(5)

# Finally
# Als dynamisch tarief < 0, verminder PV zodat injectie beperkt wordt
itemdynprice = openhab.get_item('ElecDynPrice')
maxPV = 100.0
regPV = 100.0
actPV = 0.0
regPV2 = 100.0

# # Stop PV2 if dyn price < 0
# cpv2 = ModbusClient()
#
# cpv2.host = SERVER_HOST_PV2
# cpv2.port = SERVER_PORT_PV2
# cpv2.unit_id = SERVER_UNIT_ID_PV2
# cpv2.debug = True
#
# # open or reconnect TCP to server
# if not cpv2.is_open:
#     if not cpv2.open():
#         logger.error(f"unable to connect to {SERVER_HOST_PV2} : {SERVER_PORT_PV2}")
#
# if cpv2.is_open:
#     regs = cpv2.read_holding_registers(41255, 1)
#     logger.debug(f"PV2: read from 41225: {regs}")
#     regPV2 = regs[0] / 100.0
#
# # if open() is ok, write register (modbus function 0x03)
# if cpv2.is_open:
#     if itemdynprice.state == 0:
#         if batSoC >= 99:
#             regs = cpv2.write_single_register(41255, 0)
#             logger.debug(f"PV2: write to 41225: {regs}")
#     elif itemdynprice.state < 0:
#         regs = cpv2.write_single_register(41255, 0)
#         logger.debug(f"PV2: write to 41225: {regs}")
#     elif regPV2 == 0:
#         regs = cpv2.write_single_register(41255, 10000)     # = 100%
#         logger.debug(f"PV2: write to 41225: {regs}")
#
# cpv2.close()


cpv = ModbusClient()

# uncomment this line to see debug message
cpv.debug = True

# define modbus server host, port
cpv.host = SERVER_HOST_PV
cpv.port = SERVER_PORT_PV
cpv.unit_id = SERVER_UNIT_ID_PV

# open or reconnect TCP to server
if not cpv.is_open:
    if not cpv.open():
        logger.error(f"PV: unable to connect to {SERVER_HOST_PV} : {SERVER_PORT_PV}")

# Lees huidig ingestelde limitatie
if cpv.is_open:
    regs = cpv.read_holding_registers(41255, 1)
    logger.debug(f"PV: read from 41225: {regs}")
    regPV = regs[0] / 100.0
    if regPV != 0:
        actPV = 100.0 * sunP / regPV

if itemdynprice.state < 0:
    batextra = (2500.0 + batP) if batSoC < 99 else 0.0

    maxPV = 100.0 if actPV == 0.0 else 100.0 * (sunP + netP + batextra + 50.0) / actPV

    if maxPV > 100.0:
        maxPV = 100.0
    elif maxPV < 0.0:
        maxPV = 0.0
else:
    maxPV = 100.0

if regPV != maxPV:
    # if open() is ok, write register (modbus function 0x03)
    if cpv.is_open:
        regs = cpv.write_single_register(41255, int(100.0 * maxPV))
        logger.debug(f"PV: write to 41225: {regs}")

cpv.close()


# Limit second inverter to same level
if regPV != maxPV:
    cpv2 = ModbusClient()

    cpv2.host = SERVER_HOST_PV2
    cpv2.port = SERVER_PORT_PV2
    cpv2.unit_id = SERVER_UNIT_ID_PV2
    cpv2.debug = True

    # open or reconnect TCP to server
    if not cpv2.is_open:
        if not cpv2.open():
            logger.error(f"unable to connect to {SERVER_HOST_PV2} : {SERVER_PORT_PV2}")

    # if open() is ok, write register (modbus function 0x03)
    if cpv2.is_open:
        regs = cpv2.write_single_register(41255, int(100.0 * maxPV))
        logger.debug(f"PV2: write to 41225: {regs}")

    cpv2.close()


logger.info(f"**PVlimit** Previous setting: {regPV:.1f}%, Sun Power: {sunP:.1f}, Max PV Power: {actPV:.1f}W, "
            f"PV2: {regPV2:.1f}%")
logger.info(f"**PVlimit** Dyn price: {itemdynprice.state:.2f}, Net Power: {netP:.1f}W, Bat Power: {batP:.1f}W, "
            f"Max PV Power: {maxPV:.1f}%")
logDict = {'time': datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 'timeslot': timeslot,
           'MaxPHPload': maxPeakPowerThisMonth,
           'HPbeON': HPbeON, 'HPbeSt': opMode0,
           'HPboON': HPboON, 'HPboSt': opMode1,
           'HPwwON': HPwwON, 'HPwwSt': opMode2, 'Warmtepomp': ElecHPAvg,
           'MaxPEVload': availablePowerEV,
           'EVON': EVON, 'EVcode': int(iMax), 'EVpower': itemEVPower.state,
           'MaxPBatload': availablePowerBat, 'BatON': BatON, 'BatLocked': get_superglobal('batLocked'),
           'BatLoadPower': BatLoadPower, 'BatterySoC': batSoC,
           'BatTarget': batTarget, 'BatMaxDischarge': maxDischarge, 'LoadBat': loadBat,
           'PVprevSet': regPV, 'PVSunPower': sunP, 'ActPVPower': actPV,
           'DynPrice': itemdynprice.state, 'NetPower': netP, 'BatPower': batP,
           'MaxPVPower': maxPV}

field_namesCSV = ['time', 'timeslot',
                  'MaxPHPload',
                  'HPbeON', 'HPbeSt',
                  'HPboON', 'HPboSt',
                  'HPwwON', 'HPwwSt', 'Warmtepomp',
                  'MaxPEVload',
                  'EVON', 'EVcode', 'EVpower',
                  'MaxPBatload', 'BatON', 'BatLocked',
                  'BatLoadPower', 'BatterySoC',
                  'BatTarget', 'BatMaxDischarge', 'LoadBat',
                  'PVprevSet', 'PVSunPower', 'ActPVPower',
                  'DynPrice', 'NetPower', 'BatPower',
                  'MaxPVPower']
CSVfilename = '/mnt/sharedfolder/home-log-' + str(date.today()) + '.csv'
if not Path(CSVfilename).is_file():
    append_list_as_row(CSVfilename, field_namesCSV)
append_dict_as_row(CSVfilename, logDict, field_namesCSV)


# Store some values in database at empty locations
SMApartsInv['cosphi1'] = maxPV
SMApartsInv['cosphi1unit'] = '%'
SMApartsInv['pconsumecounter'] = itemdynprice.state
SMApartsInv['pconsumecounterunit'] = 'Eur/MWh'
SMApartsInv['qconsume'] = 100.0 * sunP / regPV
SMApartsInv['qconsumeunit'] = 'W'

# Remove High Precision Counters in file to be uploaded
empartsMain_LP = {key: val for key, val in empartsMain.items() if key[-2:] != 'HP'}
empartsPV_LP = {key: val for key, val in empartsPV.items() if key[-2:] != 'HP'}
empartsHP_LP = {key: val for key, val in empartsHP.items() if key[-2:] != 'HP'}

append_dict_as_row(filenameUpload, empartsMain_LP, field_names)
append_dict_as_row(filenameUpload, empartsPV_LP, field_names)
append_dict_as_row(filenameUpload, empartsHP_LP, field_names)
append_dict_as_row(filenameUpload, SMApartsInv, field_names)
append_dict_as_row(filenameUpload, SMApartsInv2, field_names)
append_dict_as_row(filenameUpload, SMApartsBat, field_names)

# Transfer file
cnopts = pysftp.CnOpts()
cnopts.hostkeys.load('/home/userX/.ssh/known_hosts')
logger.setLevel(logging.ERROR)

with pysftp.Connection(host=myHostname, username=myUsername, password=myPassword, cnopts=cnopts) as sftp:
    # print "Connection successfully established ... "

    sftp.put(filenameUpload, '/home/userX/data/today.csv')

    sftp.close()

logger.setLevel(logging.DEBUG)
logger.info(f"End {__name__} \n")
