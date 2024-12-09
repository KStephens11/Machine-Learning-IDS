import numpy as np

class FlowSession:
    def __init__(self, packet, direction):
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst
        self.src_port = packet[packet.transport_layer].srcport
        self.dst_port = packet[packet.transport_layer].dstport
        self.proto = packet.ip.proto
        self.timestamp = packet.sniff_time.timestamp()
        self.packet_last_seen = self.timestamp

        # Flow statistics
        self.total_bytes = 0
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.fwd_pkt_len_list = []
        self.bwd_pkt_len_list = []

        # Packet length statistics
        self.fwd_pkt_len_max = 0
        self.fwd_pkt_len_min = float('inf')
        self.bwd_pkt_len_max = 0
        self.bwd_pkt_len_min = float('inf')
        
        # IAT
        self.flow_packet_timestamps = []
        self.fwd_packet_timestamps = []
        self.bwd_packet_timestamps = []
        
        # TCP flags counters
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0

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
    
    def set_packet_last_seen(self, packet):
        self.packet_last_seen = packet.sniff_time.timestamp()
    
    def new_packet(self, packet, direction):
        self.set_packet_last_seen(packet)
        self.total_bytes += len(packet)
        
        self.flow_packet_timestamps.append(self.packet_last_seen)

        if direction == "FWD":
            self.process_forward_packet(packet)
            self.fwd_packet_timestamps.append(self.packet_last_seen)
        elif direction == "BWD":
            self.process_backward_packet(packet)
            self.bwd_packet_timestamps.append(self.packet_last_seen)
        
        # Update TCP flags count
        if "TCP" in packet:
            self.update_tcp_flags(packet)

    def process_forward_packet(self, packet):
        self.tot_fwd_pkts += 1
        self.fwd_pkt_len_list.append(int(packet.length))
        self.fwd_pkt_len_max = max(self.fwd_pkt_len_max, int(packet.length))
        self.fwd_pkt_len_min = min(self.fwd_pkt_len_min, int(packet.length))

    def process_backward_packet(self, packet):
        self.tot_bwd_pkts += 1
        self.bwd_pkt_len_list.append(int(packet.length))
        self.bwd_pkt_len_max = max(self.bwd_pkt_len_max, int(packet.length))
        self.bwd_pkt_len_min = min(self.bwd_pkt_len_min, int(packet.length))

    def update_tcp_flags(self, packet):
        self.fin_flag_cnt += packet.tcp.flags_fin.int_value
        self.syn_flag_cnt += packet.tcp.flags_syn.int_value
        self.rst_flag_cnt += packet.tcp.flags_reset.int_value
        self.psh_flag_cnt += packet.tcp.flags_push.int_value
        self.ack_flag_cnt += packet.tcp.flags_ack.int_value
        self.urg_flag_cnt += packet.tcp.flags_urg.int_value
        
    def update_IAT(self, packet_timestamp_list):
        if len(packet_timestamp_list) < 2:
            return 0, 0, 0, 0, 0
        
        iat_list = []
        
        for i in range(1, len(packet_timestamp_list)):
            iat = packet_timestamp_list[i] - packet_timestamp_list[i - 1]
            iat_list.append(iat)
        
        return np.mean(iat_list), np.std(iat_list), np.max(iat_list), np.min(iat_list), np.sum(iat_list)
        
    
    def get_final_data(self):
        
        self.flow_duration = round((self.packet_last_seen - self.timestamp) * 1000)

        # Calculate flow statistics like bytes/s, pkts/s, etc.
        flow_byts_s = self.total_bytes / self.flow_duration if self.flow_duration else 0
        flow_pkts_s = (self.tot_fwd_pkts + self.tot_bwd_pkts) / self.flow_duration if self.flow_duration else 0

        fwd_pkt_len_mean = np.mean(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0
        
        fwd_pkt_len_std = np.std(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        bwd_pkt_len_std = np.std(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0
        
        # Set fwd and bwd pkt len is still inf, set to max
        if self.fwd_pkt_len_min == float('inf'):
            self.fwd_pkt_len_min = self.fwd_pkt_len_max
        if self.bwd_pkt_len_min == float('inf'):
            self.bwd_pkt_len_min = self.bwd_pkt_len_max
            
        # IAT values
        
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, flow_iat_total = self.update_IAT(self.flow_packet_timestamps)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min, fwd_iat_total = self.update_IAT(self.fwd_packet_timestamps)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, bwd_iat_total = self.update_IAT(self.bwd_packet_timestamps)
        
        final_data = (self.flow_duration, self.tot_fwd_pkts, self.tot_bwd_pkts, self.fwd_pkt_len_max, 
                      self.fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std, self.bwd_pkt_len_max, 
                      self.bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std, flow_byts_s, flow_pkts_s,
                      flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                      fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
                      bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,)
        
        # Output data to file
        output_file = open("output_data.txt","a")
        output_file.write(str(final_data) + '\n')
        output_file.close()
        
        return final_data
