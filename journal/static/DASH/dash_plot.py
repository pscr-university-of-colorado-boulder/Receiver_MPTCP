from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
import time
import datetime
import os
import sys
import matplotlib.pyplot as plt
import numpy as np

if(len(sys.argv)<2):
        print ("Usage : "+sys.argv[0]+" <stats_file>")
        exit(0)

filename = sys.argv[1]


fp = open(filename, 'r')


bitrates=[]
rbitrates=[]
throughputs=[]
buffers=[]
times=[]

line = fp.readline()
while line:
	line = fp.readline()
	fields=line.strip().split(" ")
        print fields
        if(len(fields)<5):
            continue
	time=float(fields[0])
	times.append(time)
	buffert=float(fields[2])
	buffers.append(buffert)	
	bitrate=float(fields[5])
	bitrates.append(bitrate)
        throughput=float(fields[7])
        throughputs.append(throughput)
	print (time,buffert,bitrate,throughput)	


print "bitrate:",sum(bitrates)/len(bitrates),"buffer level:",sum(buffers)/len(buffers),"throughput:",sum(throughputs)/len(throughputs)
count=0
for i in buffers:
    if(i<1):
        count+=1

print "Total stalls:",count
# for i in range(0,len(throughputs)):
# 	throughputs[i]*=8

#imgname=filename.split("_")[0]
'''
if(len(bitrates)>2):
	plt.plot(times,bitrates,label="bitrates")
	plt.xlabel("Time in s")
	plt.ylabel("Bitrate in bps")
	plt.xlim(left=min(times),right=max(times))	
	plt.ylim(top=max(bitrates),bottom=min(bitrates))
	plt.savefig(imgname+'_bitrates.pdf',bbox_inches='tight')


	plt.plot(times,buffers,label="Buffer length")
	plt.xlabel("Time in s")
	plt.ylabel("Buffer length in s")	
	plt.xlim(left=min(times),right=max(times))
	plt.ylim(top=max(buffers),bottom=min(buffers))
	plt.savefig(imgname+'_buffers.pdf',bbox_inches='tight')


	plt.plot(times,framedrops,label="Frame Drop")
	plt.xlabel("Time in s")
	plt.ylabel("Frame Drop count")	
	plt.xlim(left=min(times),right=max(times))
	plt.ylim(top=max(framedrops),bottom=min(framedrops))
	plt.savefig(imgname+'_framedrops.pdf',bbox_inches='tight')


	plt.plot(times,throughputs,label="throughput")
	plt.xlabel("Time in s")
	plt.ylabel("throughput in bps")	
	plt.xlim(left=min(times),right=max(times))
	plt.ylim(top=max(throughputs),bottom=min(throughputs))
	plt.savefig(imgname+'_throughputs.pdf',bbox_inches='tight')
'''
