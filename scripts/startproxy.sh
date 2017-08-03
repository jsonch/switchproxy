# copies relevant files to the pica 8 switch @ 10.1.1.1
LOCALIP=127.0.0.1
LOCALPORT=9999
REMOTEIP=10.1.1.2
REMOTEPORT=6633
TIMEOUT=5000
INTERVAL=1000
MINTIME=4000
FASTSOCKETINTERFACE=eth1

# set the controller to the local proxy monitor.
ovs-vsctl set-controller s1 tcp:127.0.0.1:9999
# bring up local interface.
sudo ifconfig $FASTSOCKETINTERFACE up promisc
# start proxy.
sudo ./simpleproxy $LOCALIP $LOCALPORT $REMOTEIP $REMOTEPORT $FASTSOCKETINTERFACE $TIMEOUT $INTERVAL $MINTIME
