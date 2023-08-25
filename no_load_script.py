from datetime import datetime
import time
from pyModbusTCP.client import ModbusClient

stoptime = datetime(2022, 7, 24, 12, 48, 0, 0)

SERVER_HOST = "192.168.2.101"
SERVER_PORT = 502

c = ModbusClient()

# uncomment this line to see debug message
c.debug = True

# define modbus server host, port
c.host = SERVER_HOST
c.port = SERVER_PORT
c.unit_id = 3
paraList = [0, 0, 0, 0, 0, 0, 0, 2500, 0, 0]

nowtime = datetime.now()
while nowtime < stoptime:

    # open or reconnect TCP to server
    if not c.is_open:
        if not c.open():
            print("unable to connect to " + SERVER_HOST + ":" + str(SERVER_PORT))

    # if open() is ok, write register (modbus function 0x03)
    if c.is_open:
        regs = c.write_multiple_registers(40236, [0, 2424])
        print("write to 40236: "+str(regs))

        regs = c.write_multiple_registers(40793, paraList)
        print("write to 40793: "+str(regs))

    #    regs = c.write_multiple_registers(40151, [0, 802])
    #    print("write to 40151: "+str(regs))

    #    regs = c.write_multiple_registers(40149, [0x000, 0])
    #    print("write to 40149: "+str(regs))

    c.close()

    print(nowtime)
    print(paraList)
    time.sleep(90)
    nowtime = datetime.now()
