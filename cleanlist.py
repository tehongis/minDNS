/*  */

f = open('minDNS.block','r')
lines = f.readlines()
f.close()

for line in lines:
    line = line.strip()
    line = line.lstrip()
    if line.startswith('#'):
        continue
    if line=='':
        continue
    if '#' in line:
        line=line[:line.index('#')]
        line=line.strip()        

    if line.count('.')<2:
        server=line
    else:
        pos = line.index('.')
        server = line[pos:]
        server = '*'+server
    print(server)

    


