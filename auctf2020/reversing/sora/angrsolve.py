#!/usr/bin/python3
import angr
from pwn import *

project = angr.Project('sora')
simgr = project.factory.simgr()



simgr.explore(find=0x4012aa)

p = process(['./sora'])

p.sendline(simgr.one_found.posix.dumps(0))

print(p.read().decode())
