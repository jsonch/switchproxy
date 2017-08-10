# install static routes between h1 and h2.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# start with:
# sudo ryu-manager staticSwitch.py --ofp-tcp-listen-port=6633
class StaticSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print ("switch connected to controller.")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=1)

        # add some static routes into the network. 
        match = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 2, match, actions, table_id=1)        

        match = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 2, match, actions, table_id=1)        

        # add forwarding rule for broadcast packets.      
        match = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 2, match, actions, table_id=1)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=1):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch        
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	print("Packet in!",eth.src,eth.dst)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
			# print ("I figured out that %s is at %s!"%(dst, dpid))
			# self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        else:
            out_port = ofproto.OFPP_FLOOD

        out_port = ofproto.OFPP_FLOOD # flood no matter what. Never learn.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        # matching on in_port assumes that mac address 
        # never changes. So you can only get correct timings 
        # if you send from the host's real mac address.
        # that's another thing that you can learn about the network's configuration..
        # install a flow rule no matter what..
        if 1 == 0:
        # if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
