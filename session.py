<<<<<<< HEAD
import numpy as np

class FlowSession:
    def __init__(self, packet, direction):
=======
class FlowSession:
    def __init__(self, packet):
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst
        
        if "TCP" in packet:
            self.src_port = packet.tcp.srcport
            self.dst_port = packet.tcp.dstport
            
        if "UDP" in packet:
            self.src_port = packet.udp.srcport
            self.dst_port = packet.udp.dstport
            
        self.fwd_session = self.src_ip + self.dst_ip + self.src_port + self.dst_port
        self.bwd_session = self.dst_ip + self.src_ip + self.dst_port + self.src_port
        
        self.proto = packet.ip.proto
        
        self.timestamp = packet.sniff_time.timestamp()
<<<<<<< HEAD
        self.packet_last_seen = self.timestamp
        self.get_flow_last_seen = 0
        self.flow_duration = 0
        
        self.total_bytes = 0
=======
        self.packet_last_timestamp = self.timestamp
        
        self.flow_duration = self.timestamp - self.packet_last_timestamp
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        
        self.totlen_fwd_pkts = 0
        self.totlen_bwd_pkts = 0
        
        self.fwd_pkt_len_max = 0
        self.fwd_pkt_len_min = 0
        self.fwd_pkt_len_mean = 0
        self.fwd_pkt_len_std = 0
        
<<<<<<< HEAD
        self.fwd_pkt_len_list = []
        self.bwd_pkt_len_list = []
        
=======
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        self.bwd_pkt_len_max = 0
        self.bwd_pkt_len_min = 0
        self.bwd_pkt_len_mean = 0
        self.bwd_pkt_len_std = 0
        
        self.flow_byts_s = 0
        self.flow_pkts_s = 0
<<<<<<< HEAD
        
=======
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        self.flow_iat_mean = 0
        self.flow_iat_std = 0
        self.flow_iat_max = 0
        self.flow_iat_min = 0
        
        self.fwd_iat_tot = 0
        self.fwd_iat_mean = 0
        self.fwd_iat_std = 0
        self.fwd_iat_max = 0
        self.fwd_iat_min = 0
        
        self.bwd_iat_tot = 0
        self.bwd_iat_mean = 0
        self.bwd_iat_std = 0
        self.bwd_iat_max = 0
        self.bwd_iat_min = 0
        
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        self.fwd_pkts_s = 0
        self.bwd_pkts_s = 0
        
        self.pkt_len_min = 0
        self.pkt_len_max = 0
        self.pkt_len_mean = 0
        self.pkt_len_std = 0
        self.pkt_len_var = 0
        
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0
        self.cwe_flag_cnt = 0
        self.ece_flag_cnt = 0
        
        self.down_up_ratio = 0
        
        self.pkt_size_avg = 0
        
        self.fwd_seg_size_avg = 0
        self.bwd_seg_size_avg = 0
        
        self.fwd_byts_b_avg = 0
        self.fwd_pkts_b_avg = 0
        self.fwd_blk_rate_avg = 0
        
        self.bwd_byts_b_avg = 0
        self.bwd_pkts_b_avg = 0
        self.bwd_blk_rate_avg = 0
        
        self.subflow_fwd_pkts = 0
        self.subflow_fwd_byts = 0
        self.subflow_bwd_pkts = 0
        self.subflow_bwd_byts = 0
        
        self.init_fwd_win_byts = 0
        self.init_bwd_win_byts = 0
        
        self.fwd_act_data_pkts = 0
        self.fwd_seg_size_min = 0
        
        self.active_mean = 0
        self.active_std = 0
        self.active_max = 0
        self.active_min = 0
        
        self.idle_mean = 0
        self.idle_std = 0
        self.idle_max = 0
        self.idle_min = 0
        
           
    def get_src_ip(self):
        return self.src_ip
    
<<<<<<< HEAD
    def get_dst_ip(self):
        return self.dst_ip
    
    def get_packet_last_seen(self):
        return self.packet_last_seen
    
    def set_packet_last_seen(self, packet):
        self.packet_last_seen = packet.sniff_time.timestamp()
    
    def new_packet(self, packet, direction):
        
        self.set_packet_last_seen(packet)
        
        self.total_bytes += len(packet)
        
        # Check if packet is fwd direction
        if direction  == "FWD":
            
            # Increase fwd total
            self.tot_fwd_pkts += 1;
            
            # Add to total fwd packet lenght
            self.totlen_fwd_pkts = self.totlen_fwd_pkts + int(packet.length)
            
            # Check if the packet is the largest yet
            if (self.fwd_pkt_len_max < int(packet.length)):
                self.fwd_pkt_len_max = int(packet.length)
            
            # Check if the packet is the smallest yet
            if (self.fwd_pkt_len_min > int(packet.length)):
                self.fwd_pkt_len_min = int(packet.length)
            
            # Append packet lenght to the forward packet length list
            self.fwd_pkt_len_list.append(int(packet.length))
            
            
        # Check if packet is bwd direction
        if direction  == "BWD":
            
            # Increase bwd total
            self.tot_bwd_pkts += 1;
            
            # Add to total bwd packet lenght
            self.totlen_bwd_pkts = self.totlen_bwd_pkts + int(packet.length)
            
            # Check if the packet is the largest yet
            if (self.bwd_pkt_len_max < int(packet.length)):
                self.bwd_pkt_len_max = int(packet.length)
            
            # Check if the packet is the smallest yet
            if (self.bwd_pkt_len_min > int(packet.length)):
                self.bwd_pkt_len_min = int(packet.length)
            
            # Append packet lenght to the backward packet lenght
            self.bwd_pkt_len_list.append(int(packet.length))
                
            
        # Add Set flags to count
=======
    def get_fin_count(self):
        return self.fin_flag_cnt
    
    def get_rst_count(self):
        return self.rst_flag_cnt
    
    def get_syn_count(self):
        return self.syn_flag_cnt
    
    def get_timestamp(self):
        return self.timestamp
        
    def get_packet_last_timestamp(self):
        return self.packet_last_timestamp
    
    def new_packet(self, packet):
        self.packet_last_timestamp = packet.sniff_time.timestamp()
        self.flow_duration = self.packet_last_timestamp - self.timestamp
        
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        if "TCP" in packet:
            self.fin_flag_cnt += packet.tcp.flags_fin.int_value
            self.syn_flag_cnt += packet.tcp.flags_syn.int_value
            self.rst_flag_cnt += packet.tcp.flags_reset.int_value
            self.psh_flag_cnt += packet.tcp.flags_push.int_value
            self.ack_flag_cnt += packet.tcp.flags_ack.int_value
            self.urg_flag_cnt += packet.tcp.flags_urg.int_value
            self.cwe_flag_cnt += packet.tcp.flags_cwr.int_value
            self.ece_flag_cnt += packet.tcp.flags_ece.int_value
    
    
<<<<<<< HEAD
    def get_final_data(self):
        
        self.flow_duration = self.get_packet_last_seen() - self.timestamp
        
        # Bytes/s
        if self.total_bytes != 0 and self.flow_duration != 0:
            self.flow_byts_s = self.total_bytes / self.flow_duration
        else:
            self.flow_byts_s = 0
        
        # Packet len mean
        if self.flow_duration > 0:
            self.fwd_pkt_len_mean = self.totlen_fwd_pkts / self.tot_fwd_pkts
        else:
            self.fwd_pkt_len_mean = 0
            
        if self.tot_bwd_pkts != 0:
            self.bwd_pkt_len_mean = self.totlen_bwd_pkts / self.tot_bwd_pkts
        else:
            self.bwd_pkt_len_mean = 0
        
        # Packet len std
        if self.fwd_pkt_len_list:
            self.fwd_pkt_len_std = np.std(self.fwd_pkt_len_list)
        else:
            self.fwd_pkt_len_std = 0
            
        if self.bwd_pkt_len_list:
            self.bwd_pkt_len_std = np.std(self.bwd_pkt_len_list)
        else:
            self.bwd_pkt_len_std = 0;
        
        
        return(self.flow_duration, self.total_bytes, self.flow_byts_s)
        
=======
    def get_data(self):
        pass
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
        
        

