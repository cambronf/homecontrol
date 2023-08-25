from pyModbusTCP.client import ModbusClient

SERVER_HOST = "192.168.2.100"
SERVER_PORT = 502

c = ModbusClient()

# uncomment this line to see debug message
c.debug = True

# define modbus server host, port
c.host = SERVER_HOST
c.port = SERVER_PORT
c.unit_id = 3
paraList = [0, 0, 0, 0]

# open or reconnect TCP to server
if not c.is_open:
    if not c.open():
        print("unable to connect to " + SERVER_HOST + ":" + str(SERVER_PORT))

# if open() is ok, write register (modbus function 0x03)
if c.is_open:
    regs = c.write_multiple_registers(41251, [0, 2000])
    # regs = c.write_single_register(41255, 0)
    print("write to 40023: "+str(regs))
c.close()

print(paraList)
