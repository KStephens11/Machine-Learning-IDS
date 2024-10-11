import pyshark
from session import Session
capture = pyshark.LiveCapture(interface='wlan0')


current_sessions = {}

for packet in capture:
    try:
        if "IP" in packet:
            timestamp = packet.sniff_time.timestamp()
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            proto_num = packet.ip.proto
            
            if "TCP" in packet:
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            
            if "UDP" in packet:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                
            fwd_session = src_ip + dst_ip + src_port + dst_port
            bwd_session = dst_ip + src_ip + dst_port + src_port
            
            if fwd_session in current_sessions.keys():
                pass
            elif bwd_session in current_sessions.keys():
                pass
            else:
                session = Session(packet)
                current_sessions[fwd_session] = session
            
#         if "IPV6" in packet:
#             src_ip = packet.ipv6.src
#             dst_ip = packet.ipv6.dst
#             proto_num = packet.ipv6.nxt
        
        for selected_session in current_sessions.keys():
            #print(current_sessions[selected_session].get_src_ip())
            print(str(len(current_sessions)))

    except AttributeError as error:
        pass