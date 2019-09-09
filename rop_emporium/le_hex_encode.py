import argparse

def batch(it, n):                 
    l = len(it)                   
    for i in range(0, l, n):      
        yield it[i:min(i + n, l)] 


parser = argparse.ArgumentParser()
parser.add_argument("string", type=str)

args = parser.parse_args()

for i in batch(args.string, 4):
    print("0x" + "".join([hex(ord(l))[2:] for l in i[::-1]]) + " : " + i) 

