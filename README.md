Simple OFX-like proxy between a switch and controller.

This is a hybrid openflow proxy / packet processor designed to run on a switch. It proxies the OpenFlow connection between a switch and a controller, and also has a fast path connection to the switch's forwarding engine. 

Current capabilities: 
- inspecting, intercepting, and modifying messages between the controller and switch.
- processing packets on the switch with arbitrary C++ functions, using a fast raw socket between a FE port and the proxy that allows the FE to avoid packet_in messages, and any slow busses/firmware/drivers that usually connect the FE to the switch CPU. 
- sending custom control messages to the controller. 

Limitations: 
- Messy. 
- Almost everything is hard coded. 
- Only has structs to generate a few custom OpenFlow 1.2 controller messages. 
- Messy. 

Usage: 

sudo ./simpleproxy $LOCALIP $LOCALPORT $REMOTEIP $REMOTEPORT $FASTSOCKETINTERFACE $TIMEOUT $INTERVAL $MINTIME

$LOCALIP/$LOCALPORT = IP/port of openflow agent on switch
$REMOTEIP/$REMOTEPORT = IP/port of the remote openflow controller
$FASTSOCKETINTERFACE = the interface that connected to a FE port

Other parameters are specific to using this code as a timing proxy that sends the switch a default forwarding instruction for a packet when it does not receive a response from the controller within a bounded period of time. See scripts/startproxy.sh and the paper for more details: http://dl.acm.org/citation.cfm?id=2991081

What the code does: 

1) launches a thread to send a keepalive ping to the OF agent on the switch. 
2) launches a thread that uses select to move packets from the OF agent socket to the controller socket (and vice versa), and listen for packets to process on the fast socket interface to the FE. 