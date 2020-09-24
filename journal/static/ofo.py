import sys

if(len(sys.argv)<2):
    print ("Usage error")
    exit(0)
filename=sys.argv[1]
fd=open(filename,"r")

Lines = fd.readlines()
ofo=[]
# Strips the newline character
for line in Lines:
    ofo.append(int(line.split("\n")[0].split(" ")[-1]))

print ("avg:",sum(ofo)/len(ofo),"max:",max(ofo))
