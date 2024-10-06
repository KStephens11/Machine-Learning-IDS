import pyshark

def print_callback(packet):
    print(packet)

capture = pyshark.LiveCapture(interface='wlan0')


for packet in capture:
    try:
        src_ip = None
        dst_ip = None
        proto_num = None
        
        if "IP" in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto_num = packet.ip.proto
            
            
        if "IPV6" in packet:
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            proto_num = packet.ipv6.nxt
        
        timestamp = float(packet.sniff_time.timestamp())
        if src_ip != None and dst_ip != None:
            print(src_ip, dst_ip, proto_num, timestamp)

    except AttributeError as error:
        pass