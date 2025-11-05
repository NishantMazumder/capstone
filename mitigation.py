from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switchm
from datetime import datetime

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score


class SimpleMonitor13(switchm.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        # train model (will raise/log if dataset missing)
        try:
            self.flow_training()
        except Exception as e:
            self.logger.exception("Error during initial model training: %s", e)
            # model might be missing — set to None
            self.flow_model = None

        end = datetime.now()
        self.logger.info("Training time: %s", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.logger.debug('send stats request: %016x', dp.id)
                self._request_stats(dp)
            hub.sleep(10)

            self.logger.debug('Running flow_predict()')
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now().timestamp()
        body = ev.msg.body

        # write in append mode; create header if file missing or empty
        filename = "PredictFlowStatsfile.csv"
        write_header = False
        try:
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                write_header = True
        except Exception:
            write_header = True

        with open(filename, "a") as file0:
            if write_header:
                file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

            for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
                (flow.match.get('eth_type'), flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'), flow.match.get('ip_proto'))):

                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match.get('ip_proto', 0)

                icmp_code = -1
                icmp_type = -1
                tp_src = 0
                tp_dst = 0

                if ip_proto == 1:
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                elif ip_proto == 6:
                    tp_src = stat.match.get('tcp_src', 0)
                    tp_dst = stat.match.get('tcp_dst', 0)
                elif ip_proto == 17:
                    tp_src = stat.match.get('udp_src', 0)
                    tp_dst = stat.match.get('udp_dst', 0)

                flow_id = "{}{}{}{}{}".format(ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                # avoid division by zero
                duration_sec = stat.duration_sec if stat.duration_sec and stat.duration_sec > 0 else 1e-6
                duration_nsec = stat.duration_nsec if stat.duration_nsec and stat.duration_nsec > 0 else 1e-6

                packet_count_per_second = stat.packet_count / duration_sec if stat.packet_count else 0
                packet_count_per_nsecond = stat.packet_count / duration_nsec if stat.packet_count else 0
                byte_count_per_second = stat.byte_count / duration_sec if stat.byte_count else 0
                byte_count_per_nsecond = stat.byte_count / duration_nsec if stat.byte_count else 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                    timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, icmp_code, icmp_type,
                    stat.duration_sec, stat.duration_nsec,
                    stat.idle_timeout, stat.hard_timeout,
                    stat.flags, stat.packet_count, stat.byte_count,
                    packet_count_per_second, packet_count_per_nsecond,
                    byte_count_per_second, byte_count_per_nsecond))

    def flow_training(self):

        self.logger.info("Flow Training ...")

        # expect dataset.csv in same folder
        df = pd.read_csv('FlowStatsfile.csv')

        # ensure columns that were ip-like are str and same preprocessing used during predict
        # the original script replaced '.' in some columns — keep that behaviour
        df.iloc[:, 2] = df.iloc[:, 2].astype(str).str.replace('.', '', regex=False)
        df.iloc[:, 3] = df.iloc[:, 3].astype(str).str.replace('.', '', regex=False)
        df.iloc[:, 5] = df.iloc[:, 5].astype(str).str.replace('.', '', regex=False)

        X_flow = df.iloc[:, :-1].values.astype('float64')
        y_flow = df.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        classifier = KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)
        y_flow_pred_train = self.flow_model.predict(X_flow_train)

        self.logger.info("------------------------------------------------------------------------------")

        self.logger.info("Confusion Matrix")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        self.logger.info(cm)

        # optional: log accuracy
        try:
            acc = accuracy_score(y_flow_test, y_flow_pred)
            self.logger.info("Test Accuracy = %.2f%%", acc * 100)
        except Exception:
            pass

    def flow_predict(self):
        # make predictions using the latest PredictFlowStatsfile.csv
        try:
            if not hasattr(self, 'flow_model') or self.flow_model is None:
                self.logger.debug("No trained model available; skipping prediction")
                return

            filename = 'PredictFlowStatsfile.csv'
            if not os.path.exists(filename):
                self.logger.debug("No PredictFlowStatsfile.csv found; skipping")
                return

            predict_flow_dataset = pd.read_csv(filename)

            # same preprocessing as training
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].astype(str).str.replace('.', '', regex=False)
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].astype(str).str.replace('.', '', regex=False)
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].astype(str).str.replace('.', '', regex=False)

            X_predict_flow = predict_flow_dataset.values.astype('float64')

            # feature count check
            expected = getattr(self.flow_model, 'n_features_in_', None)
            if expected is not None and X_predict_flow.shape[1] != expected:
                self.logger.error("Feature mismatch: model expects %s features, found %s. Skipping prediction.", expected, X_predict_flow.shape[1])
                return

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0
            ddos_rows = []

            for idx, label in enumerate(y_flow_pred):
                if label == 0:
                    legitimate_trafic += 1
                else:
                    ddos_trafic += 1
                    ddos_rows.append(idx)

            total = len(y_flow_pred)
            self.logger.info("Predicted: %s legit, %s ddos (total %s)", legitimate_trafic, ddos_trafic, total)

            if total == 0:
                return

            if (legitimate_trafic / total * 100) > 80:
                self.logger.info("Traffic is Legitimate!")
                # clear mitigation if previously set
                if getattr(self, 'mitigation', 0) == 1:
                    self.logger.info("Clearing mitigation mode and unblocking ports...")
                    self.mitigation = 0
                    for dpid, ports in list(getattr(self, 'blocked_ports', {}).items()):
                        if dpid in self.datapaths:
                            dp = self.datapaths[dpid]
                            for p in list(ports):
                                try:
                                    self.unblock_port(dp, p)
                                except Exception as e:
                                    self.logger.exception("Error unblocking port %s on dp %s: %s", p, dpid, e)
            else:
                # identify a victim (first ddos row if present)
                victim = None
                if ddos_rows:
                    try:
                        row = ddos_rows[0]
                        victim_ip_field = predict_flow_dataset.iloc[row, 5]
                        try:
                            victim = int(str(victim_ip_field).split('.')[-1])
                        except Exception:
                            victim = None
                    except Exception as e:
                        self.logger.exception("Error extracting victim info: %s", e)

                self.logger.info("NOTICE!! DoS Attack in Progress!!!")
                if victim:
                    self.logger.info("Victim Host last-octet: %s", victim)
                else:
                    self.logger.info("Victim Host unknown")
                self.logger.info("Mitigation process in progress!")
                self.mitigation = 1

            # truncate the predict file after successful prediction to avoid unlimited growth
            with open(filename, 'w') as file0:
                file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

        except Exception as e:
            self.logger.exception("flow_predict error: %s", e)
