# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
# import joblib
# import json
# import numpy as np
# import os

# class DDoSDetector(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

#     def __init__(self, *args, **kwargs):
#         super(DDoSDetector, self).__init__(*args, **kwargs)
#         self.mac_to_port = {}
#         self.clf = joblib.load('syn_rf_model.pkl')
#         with open('features.json') as f:
#             self.features = json.load(f)

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         datapath = ev.msg.datapath
#         ofproto = datapath.ofproto
#         parser = datapath.ofproto_parser

#         # Install table-miss flow entry
#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
#                                           ofproto.OFPCML_NO_BUFFER)]
#         self.add_flow(datapath, 0, match, actions)

#     def add_flow(self, datapath, priority, match, actions):
#         ofproto = datapath.ofproto
#         parser = datapath.ofproto_parser

#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                              actions)]
#         mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
#                                 match=match, instructions=inst)
#         datapath.send_msg(mod)

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def packet_in_handler(self, ev):
#         msg = ev.msg
#         datapath = msg.datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto

#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocols(ethernet.ethernet)[0]

#         in_port = msg.match['in_port']
#         dpid = datapath.id
#         self.mac_to_port.setdefault(dpid, {})

#         dst = eth.dst
#         src = eth.src

#         self.mac_to_port[dpid][src] = in_port

#         out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
#         actions = [parser.OFPActionOutput(out_port)]

#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         tcp_pkt = pkt.get_protocol(tcp.tcp)
#         udp_pkt = pkt.get_protocol(udp.udp)

#         if ip_pkt:
#             # Dummy features — replace with real ones from flow stats later
#             sample = np.array([[5000, 10, 8, 4000, 1000]])  # Example input
#             pred = self.clf.predict(sample)

#             if pred[0] == 1:  # 1 = attack
#                 self.logger.info("DDoS detected. Dropping flow.")
#                 return

#         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
#         self.add_flow(datapath, 1, match, actions)

#         out = parser.OFPPacketOut(datapath=datapath,
#                                   buffer_id=msg.buffer_id,
#                                   in_port=in_port,
#                                   actions=actions,
#                                   data=msg.data)
#         datapath.send_msg(out)


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

import json
import joblib
import time
import numpy as np

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)

        # Load ML model and feature order
        self.model = joblib.load('syn_rf_model.pkl')  # replace if your model is named differently
        with open('features.json') as f:
            self.feature_order = json.load(f)

        self.datapaths = {}
        self.flow_stats = {}  # {(src_ip, dst_ip): [features]}

        # Start polling stats
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue

            pkt_count = stat.packet_count
            byte_count = stat.byte_count
            duration = stat.duration_sec + stat.duration_nsec / 1e9

            if duration == 0:
                continue

            flow_id = (stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'))
            if None in flow_id:
                continue

            features = {
                "Flow Duration": duration,
                "Total Fwd Packets": pkt_count,
                "Total Backward Packets": 0,
                "Fwd Packets Length Total": byte_count,
                "Bwd Packets Length Total": 0,
                "Flow Bytes/s": byte_count / duration,
                "Flow Packets/s": pkt_count / duration,
                "Packet Length Min": 60,
                "Packet Length Max": 1514,
                "Packet Length Mean": byte_count / pkt_count if pkt_count else 0,
                "Packet Length Std": 0,
                "Subflow Fwd Bytes": byte_count,
                "Subflow Bwd Bytes": 0
            }

            # Prepare input for prediction
            input_vector = [features[feat] for feat in self.feature_order]
            input_np = np.array([input_vector])

            prediction = self.model.predict(input_np)[0]
            if prediction == 1:  # Assuming 1 is DDoS
                self.logger.warning("⚠️ DDoS attack detected from %s to %s",
                                    flow_id[0], flow_id[1])
