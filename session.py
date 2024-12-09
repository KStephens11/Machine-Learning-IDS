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

        if direction == "FWD":
            self.process_forward_packet(packet)
        elif direction == "BWD":
            self.process_backward_packet(packet)
        
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

    def get_final_data(self):
        
        flow_duration = self.packet_last_seen - self.timestamp

        # Calculate flow statistics like bytes/s, pkts/s, etc.
        flow_byts_s = self.total_bytes / flow_duration if flow_duration else 0
        flow_pkts_s = (self.tot_fwd_pkts + self.tot_bwd_pkts) / flow_duration if flow_duration else 0

        fwd_pkt_len_mean = np.mean(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0
        
        fwd_pkt_len_std = np.std(self.fwd_pkt_len_list) if self.fwd_pkt_len_list else 0
        bwd_pkt_len_std = np.std(self.bwd_pkt_len_list) if self.bwd_pkt_len_list else 0
        
        # Set fwd and bwd pkt len is still inf, set to max
        if self.fwd_pkt_len_min == float('inf'):
            self.fwd_pkt_len_min = self.fwd_pkt_len_max
        if self.bwd_pkt_len_min == float('inf'):
            self.bwd_pkt_len_min = self.bwd_pkt_len_max
        
        final_data = (flow_duration, self.tot_fwd_pkts, self.tot_bwd_pkts, self.fwd_pkt_len_max, 
                      self.fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std, self.bwd_pkt_len_max, 
                      self.bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std, flow_byts_s, flow_pkts_s)
        
        # Output data to file
        output_file = open("output_data.txt","a")
        output_file.write(str(final_data) + '\n')
        output_file.close()
        
        return final_data
