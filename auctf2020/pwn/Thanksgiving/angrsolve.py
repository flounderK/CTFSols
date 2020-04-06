#!/usr/bin/python3
import angr
from pwn import *
import time

project = angr.Project('turkey')
simgr = project.factory.simgr()

simgr.run(until=lambda a: a.one_active.posix.dumps(1).find(b'Wait') > -1)
# p = remote('challenges.auctf.com', 30011)
p = process(['./turkey'])
p.send(simgr.one_active.posix.dumps(0))
time.sleep(2)

print(p.read().decode())

