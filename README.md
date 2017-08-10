OFX-like proxy between a switch and controller.

This is a hybrid openflow proxy / packet processor designed to run on a switch. It proxies the OpenFlow connection between a switch manager (i.e., the OVS agent) and a controller, and also has a fast path connection to the switch's forwarding engine, which lets it do packet processing without the overhead of the control path. 

Usage: 

make simpleproxy

sudo ./simpleproxy $LOCALIP $LOCALPORT $REMOTEIP $REMOTEPORT $FASTSOCKETINTERFACE
$LOCALIP/$LOCALPORT = IP/port of openflow agent on switch
$REMOTEIP/$REMOTEPORT = IP/port of the remote openflow controller
$FASTSOCKETINTERFACE = the interface that connected to a FE port

Demo & testing: 

There is a mininet test harness in ./mininet with a simple demo where the proxy gets a clone of every packet the switch handles. 

*start the mininet topology:*
sudo python mininet/startmn.py
- this will also: 
  1. do all the switch configuration to use the proxy, 
  2. set the controller for ovs switch s1 to localhost:9999 and,
  3. add a rule to clone every packet to the fast path interface of the proxy

*start the ryu controller, running on localhost and listening on the standard port:*
sudo ryu-manager mininet/staticSwitch.py --ofp-tcp-listen-port=6633
- this will just add some static forwarding rules

*start the proxy:*
sudo ./simpleproxy localhost 9999 localhost 6633 ofxveth1
- this will proxy between the OVS switch agent and the ryu controller. 

*run a ping test:*
- back in the mininet window, run: 
h1 ping h2
- you should see the proxy forwarding OF messages to / from the controller, and also getting clones of the datapath packets on the fast path interface. 


Modifying code: 

modify these functions in simpleproxy.cpp:

int processSwitchMessage(int outSocket, char *pkt, size_t pkt_len);

int processControllerMessage(int outSocket, char *pkt, size_t pkt_len);

void processDpMessage(int dpsock);


Limitations: 

- Does not support sending custom messages to the controller or OVS agent.

