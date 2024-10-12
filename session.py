class Session:
    def __init__(self, packet):
        
        self.timestamp = packet.sniff_time.timestamp()
        self.packet_timestamp = self.timestamp
        self.duration = self.timestamp - self.packet_timestamp
        
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst
        
        if "TCP" in packet:
            self.src_port = packet.tcp.srcport
            self.dst_port = packet.tcp.dstport
            
        if "UDP" in packet:
            self.src_port = packet.udp.srcport
            self.dst_port = packet.udp.dstport
            
        self.protocol = packet.ip.proto
        
        self.fwd_session = self.src_ip + self.dst_ip + self.src_port + self.dst_port
        self.bwd_session = self.dst_ip + self.src_ip + self.dst_port + self.src_port
        
        
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwr_count = 0
        self.ece_count = 0
        
        
        
    def get_src_ip(self):
        return self.src_ip
    
    def get_fin_count(self):
        return self.fin_count
    
    def get_rst_count(self):
        return self.rst_count
    
    def get_syn_count(self):
        return self.syn_count
    
    def get_duration(self):
        return self.duration
        
    def get_packet_timestamp(self):
        return self.packet_timestamp
    
    def new_packet(self, packet):
        self.packet_timestamp = packet.sniff_time.timestamp()
        self.duration = self.packet_timestamp - self.timestamp
        
        if "TCP" in packet:
            self.fin_count += packet.tcp.flags_fin.int_value
            self.syn_count += packet.tcp.flags_syn.int_value
            self.rst_count += packet.tcp.flags_reset.int_value
            self.psh_count += packet.tcp.flags_push.int_value
            self.ack_count += packet.tcp.flags_ack.int_value
            self.urg_count += packet.tcp.flags_urg.int_value
            self.cwr_count += packet.tcp.flags_cwr.int_value
            self.ece_count += packet.tcp.flags_ece.int_value
            
        
        

