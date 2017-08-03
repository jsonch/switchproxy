ovs-vsctl del-br s1

# set up the switch.
ovs-vsctl add-br s1 -- set bridge s1 datapath_type=pica8

# openflow 1.2
ovs-vsctl set Bridge s1 protocols=OpenFlow12

ovs-vsctl add-port s1 ge-1/1/1 -- set interface ge-1/1/1 type=pica8
ovs-vsctl add-port s1 ge-1/1/2 -- set interface ge-1/1/2 type=pica8
ovs-vsctl add-port s1 ge-1/1/3 -- set interface ge-1/1/3 type=pica8
ovs-vsctl add-port s1 ge-1/1/4 vlan_mode=trunk tag=66 -- set interface ge-1/1/4 type=pica8 -- set Interface ge-1/1/4 ofport_request=66
# set the controller.
ovs-vsctl set-controller s1 tcp:10.1.1.2:6633
