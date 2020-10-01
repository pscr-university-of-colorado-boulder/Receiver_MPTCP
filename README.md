# Receiver_MPTCP
This repository has the receiver controlled MPTCP scheduler that reduces the Out Of Order length and improves the overall MPTCP throughput by
 (i)   client-initiated   path   selection  
 (ii)  RTT-based  rate  throttling  mechanisms. 

# Steps:

Download the MPTCP code from https://github.com/multipath-tcp/mptcp
If you want to use the BPF then download MPTCP from https://github.com/hoang-tranviet/mptcp_private

Once Linux kernel is download use the mptcp_private/.. directory files to include receiver controller.

1.Enable the MPTCP option using make menuconfig under Network Configuration
2. make -j<#cores> deb-pkg LOCALVERSION="cMPTCP"
3. Install four kernel images obtained using dpkg -i *.deb

Once machine boots up.

#Server:
#iperf3:
  Run iperf3 server as "iperf3 -s -p 8080" 
 
#DASH:
  1. Set up DASH server using:
   https://github.com/Dash-Industry-Forum/dash.js
  2. In the server "/var/www/html/DASH/<dash.js> 

#Client:
#iperf3:
  iperf3 -c <server_ip> -p 8080 -R -t <duration>

#DASH client.
1. Now use the scripts in journal/static/DASH/dash_stats.py in client that opens browser window in Private mode to play DASH video.
2. Use journal/static/DASH/dash_plot.py to plot the bitrate,buffer length etc DASH parameters.

Compile the linux and load it to the receiver.
