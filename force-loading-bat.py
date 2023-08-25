import time
from pyModbusTCP.client import ModbusClient

SERVER_HOST = "192.168.2.101"
SERVER_PORT = 502

c = ModbusClient()

# uncomment this line to see debug message
c.debug = True

# define modbus server host, port
c.host = SERVER_HOST
c.port = SERVER_PORT
c.unit_id = 3

paraList40793to40801 = [0, 0, 0, 2500, 0, 0, 0, 0, 0, 0]
paraList41251 = [0, 2500]

maxLoad = 1000

paraList40149 = [0x8000, 2500]
paraList40151 = [0, 802]
paraList40149[1] = maxLoad
paraList41251[1] = maxLoad
paraList40793to40801[3] = maxLoad
waittime = 0.25

# open or reconnect TCP to server
if not c.is_open:
    if not c.open():
        print("unable to connect to " + SERVER_HOST + ":" + str(SERVER_PORT))

# if open() is ok, write register (modbus function 0x03)
if c.is_open:

    regs = c.write_multiple_registers(40236, [0, 2424])         # U32 TAGLIST
    print("write to 40236: "+str(regs))
    time.sleep(waittime)

    regs = c.write_multiple_registers(40793, paraList40793to40801)   # 4x(U32 FIX0), 1x(S32 FIX0)
    print("write to 40793-40801: "+str(regs))
    time.sleep(waittime)

    # regs = c.write_multiple_registers(40795, paraList40795)     # U32 FIX0
    # print("write to 40795: "+str(regs))
    # time.sleep(waittime)
    #
    # regs = c.write_multiple_registers(40797, paraList40797)     # U32 FIX0
    # print("write to 40797: "+str(regs))
    # time.sleep(waittime)
    #
    # regs = c.write_multiple_registers(40799, paraList40795)     # U32 FIX0
    # print("write to 40799: "+str(regs))
    # time.sleep(waittime)
    #
    # regs = c.write_multiple_registers(40801, paraList40801)     # S32 FIX0
    # print("write to 40801: "+str(regs))
    # time.sleep(waittime)

    regs = c.write_multiple_registers(41251, paraList41251)         # S32 FIX0
    print("write to 41251: "+str(regs))
    time.sleep(waittime)

    regs = c.write_multiple_registers(40151, paraList40151)     # U32 TAGLIST
    print("write to 40151: "+str(regs))
    time.sleep(waittime)

    regs = c.write_multiple_registers(40149, paraList40149)     # S32 FIXO
    print("write to 40149: "+str(regs))
    time.sleep(waittime)

c.close()

print(f"40793: {paraList40793to40801}")
# print(f"40795: {paraList40795}")
# print(f"40797: {paraList40797}")
# print(f"40799: {paraList40799}")
# print(f"40801: {paraList40801}")
print(f"40149: {paraList40149}")
print(f"40151: {paraList40151}")
print(f"41251: {paraList41251}")
