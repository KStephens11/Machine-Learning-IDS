import numpy as np

mult_scale = 1_000_000

class FlowSession:
    def __init__(self, packet):
        self.src_ip = packet.src_ip
        self.dst_ip = packet.dst_ip
        self.proto = packet.protocol

        self.src_port = packet.src_port
        self.dst_port = packet.dst_port

        self.timestamp = packet.timestamp
        self.packet_last_seen = packet.timestamp
        self.packet_previous_timestamp = packet.timestamp

        self.init_fwd_win_bytes = -1
        self.init_bwd_win_bytes = -1

        self.fwd_act_data_pkts = 0
        self.fwd_seg_size_min = 0

        # Sub Flows
        self.subflows = []

        # Active Idle
        self.active_flows = []
        self.idle_flows = []
        self.active_start = packet.timestamp
        self.active_last = packet.timestamp
        self.active_timeout = 5

        # Flow statistics
        self.total_bytes = 0
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.fwd_pkt_len_list = []
        self.bwd_pkt_len_list = []

        # IAT
        self.flow_packet_timestamps = []
        self.fwd_packet_timestamps = []
        self.bwd_packet_timestamps = []

        # TCP flag counters
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0

        self.fwd_psh_flag = 0
        self.bwd_psh_flag = 0

        self.fwd_urg_flag = 0
        self.bwd_urg_flag = 0

        self.fwd_header_len = 0
        self.bwd_header_len = 0

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port

    def get_packet_last_seen(self):
        return self.packet_last_seen

    def get_timestamp(self):
        return self.timestamp

    def new_packet(self, packet, direction):
        self.packet_last_seen = packet.timestamp
        self.total_bytes += packet.packet_size

        # Track Active and Idle
        if (self.packet_last_seen - self.active_last) > self.active_timeout:
            if self.active_last - self.active_start > 0:
                self.active_flows.append((self.active_last - self.active_start)*mult_scale)

            self.idle_flows.append((self.packet_last_seen - self.active_last)*mult_scale)
            self.active_start = self.packet_last_seen

        self.active_last = self.packet_last_seen

        #IAT Flow
        self.flow_packet_timestamps.append(self.packet_last_seen)

        if direction == "FWD":
            self.process_forward_packet(packet)

            # IAT FWD
            self.fwd_packet_timestamps.append(self.packet_last_seen)

        elif direction == "BWD":
            self.process_backward_packet(packet)

            #IAT BWD
            self.bwd_packet_timestamps.append(self.packet_last_seen)

        # Update TCP flags count
        if packet.protocol == 6:
            self.update_tcp_flags(packet)
            if packet.syn_flag == 1 and packet.ack_flag == 0:
                self.init_fwd_win_bytes = packet.win_size
            elif packet.syn_flag == 1 and packet.ack_flag == 1:
                self.init_bwd_win_bytes = packet.win_size

    def process_forward_packet(self, packet):
        self.tot_fwd_pkts += 1
        self.fwd_pkt_len_list.append(packet.packet_size)
        # TCP Header size
        self.fwd_header_len += packet.transport_header_size


        # Update Subflow
        current_subflow = self.subflows[-1]
        current_subflow["end"] = self.packet_last_seen
        current_subflow["fwd_bytes"] = packet.packet_size
        current_subflow["fwd_pkts"] += 1

        # Update flags for fwd
        if packet.protocol == 6:
            self.fwd_psh_flag += packet.psh_flag
            self.fwd_urg_flag += packet.urg_flag
            # Check TCP payload for at least 1 byte
            if packet.transport_payload_size > 0:
                self.fwd_act_data_pkts += 1


    def process_backward_packet(self, packet):
        self.tot_bwd_pkts += 1
        self.bwd_pkt_len_list.append(packet.packet_size)
        # TCP header lenght
        self.bwd_header_len += packet.transport_header_size

        # Update Subflow
        current_subflow = self.subflows[-1]
        current_subflow["end"] = self.packet_last_seen
        current_subflow["bwd_bytes"] = packet.packet_size
        current_subflow["bwd_pkts"] += 1

        # Update flags for bwd
        if packet.protocol == 6:
            self.bwd_psh_flag += packet.psh_flag
            self.bwd_urg_flag += packet.urg_flag

    def update_tcp_flags(self, packet):
        self.fin_flag_cnt += packet.fin_flag
        self.syn_flag_cnt += packet.syn_flag
        self.rst_flag_cnt += packet.rst_flag
        self.psh_flag_cnt += packet.psh_flag
        self.ack_flag_cnt += packet.ack_flag
        self.urg_flag_cnt += packet.urg_flag

    @staticmethod
    def update_iat(packet_timestamp_list):

        if len(packet_timestamp_list) <= 1:
            result =  (0, 0, 0, 0, 0)
        else:
            iat_list = []

            for i in range(1, len(packet_timestamp_list)):
                iat = (packet_timestamp_list[i]) - (packet_timestamp_list[i - 1])
                iat = iat * mult_scale
                iat_list.append(iat)

            iat_mean = round(np.mean(iat_list).item(),9)
            iat_std = round(np.std(iat_list).item(),9)
            iat_max = round(np.max(iat_list).item(),9)
            iat_min = round(np.min(iat_list).item(),9)
            iat_sum = round(np.sum(iat_list).item(),9)

            result = (iat_mean, iat_std, iat_max, iat_min, iat_sum)

        return result

    def create_subflow(self, timestamp):
        subflow = {
            "start": timestamp,
            "end": timestamp,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "fwd_pkts": 0,
            "bwd_pkts": 0
        }
        self.subflows.append(subflow)

    def get_final_data(self):

        # Calculate flow duration in micro seconds
        flow_duration = (self.packet_last_seen - self.timestamp)
        flow_duration_ms = flow_duration * mult_scale

        total_pkt_len_list = self.fwd_pkt_len_list + self.bwd_pkt_len_list

        # Calculate flow bytes/s and pkts/s
        flow_byts_s = self.total_bytes / flow_duration if flow_duration else 0
        flow_pkts_s = (self.tot_fwd_pkts + self.tot_bwd_pkts) / flow_duration if flow_duration else 0
        flow_fwd_pkts_s = self.tot_fwd_pkts / flow_duration if flow_duration else 0
        flow_bwd_pkts_s = self.tot_bwd_pkts / flow_duration if flow_duration else 0

        # Packet len sum, min and max
        total_fwd_pkt_len = sum(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        total_bwd_pkt_len = sum(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0

        fwd_pkt_len_max = max(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        fwd_pkt_len_min = min(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0

        bwd_pkt_len_max = max(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0
        bwd_pkt_len_min = min(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0

        pkt_len_min = min(total_pkt_len_list)
        pkt_len_max = max(total_pkt_len_list)

        # Packet len mean and std
        fwd_pkt_len_mean = np.mean(self.fwd_pkt_len_list).item() if self.fwd_pkt_len_list else 0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_len_list).item() if self.bwd_pkt_len_list else 0
        pkt_len_mean = np.mean(total_pkt_len_list).item() if total_pkt_len_list else 0

        fwd_pkt_len_std = np.std(self.fwd_pkt_len_list).item() if self.fwd_pkt_len_list else 0
        bwd_pkt_len_std = np.std(self.bwd_pkt_len_list).item() if self.bwd_pkt_len_list else 0
        pkt_len_std = np.std(total_pkt_len_list).item() if total_pkt_len_list else 0

        # Packet seg Averages
        fwd_seg_size_avg = np.average(self.fwd_pkt_len_list).item() if self.fwd_pkt_len_list else 0
        bwd_seg_size_avg = np.average(self.bwd_pkt_len_list).item() if self.bwd_pkt_len_list else 0

        # Packet seg Min
        fwd_seg_size_min = min(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0

        # Packet size Average
        pkt_size_avg = np.average(total_pkt_len_list).item() if total_pkt_len_list else 0

        # Packet Variance
        pkt_len_var = np.var(total_pkt_len_list).item() if total_pkt_len_list else 0

        # Inter packet arrival time values
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, flow_iat_total = self.update_iat(self.flow_packet_timestamps)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min, fwd_iat_total = self.update_iat(self.fwd_packet_timestamps)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, bwd_iat_total = self.update_iat(self.bwd_packet_timestamps)

        # Subflow values
        subflow_fwd_pkts = np.average([subflow["fwd_pkts"] for subflow in self.subflows]).item() if self.subflows else 0
        subflow_fwd_bytes = np.average([subflow["fwd_bytes"] for subflow in self.subflows]).item() if self.subflows else 0
        subflow_bwd_pkts = np.average([subflow["bwd_pkts"] for subflow in self.subflows]).item() if self.subflows else 0
        subflow_bwd_bytes = np.average([subflow["bwd_bytes"] for subflow in self.subflows]).item() if self.subflows else 0

        # Active Flow values
        active_mean = np.mean(self.active_flows).item() if self.active_flows else 0
        active_std = np.std(self.active_flows).item() if self.active_flows else 0
        active_max = max(self.active_flows) if self.active_flows else 0
        active_min = min(self.active_flows) if self.active_flows else 0

        # Idle Flow values
        idle_mean = np.mean(self.idle_flows).item() if self.idle_flows else 0
        idle_std = np.std(self.idle_flows).item() if self.idle_flows else 0
        idle_max = max(self.idle_flows) if self.idle_flows else 0
        idle_min = min(self.idle_flows) if self.idle_flows else 0

        flow_data = [self.src_ip, self.dst_ip, self.src_port,
                     self.dst_port,
                     self.proto,
                     round(flow_duration_ms),
                     self.tot_fwd_pkts, self.tot_bwd_pkts, total_fwd_pkt_len, total_bwd_pkt_len,
                     fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std,
                     bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std,
                     flow_byts_s, flow_pkts_s,
                     flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                     fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
                     bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
                     self.fwd_psh_flag, self.bwd_psh_flag, self.fwd_urg_flag, self.bwd_urg_flag,
                     self.fwd_header_len, self.bwd_header_len,
                     flow_fwd_pkts_s, flow_bwd_pkts_s,
                     pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var,
                     self.fin_flag_cnt, self.syn_flag_cnt, self.rst_flag_cnt, self.psh_flag_cnt, self.ack_flag_cnt,
                     self.urg_flag_cnt,
                     pkt_size_avg, fwd_seg_size_avg, bwd_seg_size_avg,
                     subflow_fwd_pkts, subflow_fwd_bytes, subflow_bwd_pkts, subflow_bwd_bytes,
                     self.init_fwd_win_bytes, self.init_bwd_win_bytes,
                     self.fwd_act_data_pkts, fwd_seg_size_min,
                     active_mean, active_std, active_max, active_min,
                     idle_mean, idle_std, idle_max, idle_min]

        #for x in [fwd_seg_size_min,self.init_fwd_win_bytes,self.init_bwd_win_bytes,self.rst_flag_cnt,self.ack_flag_cnt,self.bwd_psh_flag,fwd_pkt_len_mean,self.fwd_act_data_pkts,self.fwd_header_len]:
        #    if x in flow_data:
        #        flow_data.remove(x)

        # Output data to file
        output_file = open("logs/output_data.csv","a")
        output_file.write(str(flow_data[3:])[1:-1] + '\n')
        output_file.close()

        return flow_data
