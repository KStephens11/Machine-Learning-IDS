class Session:
    def __init__(self, packet):
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
        
        self.timestamp = 0
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0
        
        
    def get_src_ip(self):
        return self.src_ip

