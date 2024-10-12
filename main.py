import pyshark
from session import FlowSession
capture = pyshark.LiveCapture(interface='wlan0')


current_flows = {}
bwd_count = 0
fwd_count = 0
del_flow_count = 0
timeout = 100
timestamp = 0

for packet in capture:
    try:
        if "IP" in packet:
            timestamp = packet.sniff_time.timestamp()
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto_num = packet.ip.proto
                
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
                
            fwd_flow = src_ip + dst_ip + src_port + dst_port
            bwd_flow = dst_ip + src_ip + dst_port + src_port
            
            # Check if fwd flow
            if fwd_flow in current_flows.keys():
                fwd_count +=1
                
                # Check for Reset or Fin flag
                if "TCP" in packet and (packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1):
                    current_flows[fwd_flow].new_packet(packet)
                    del(current_flows[fwd_flow])
                    del_flow_count += 1
                
                # Update packet
                else:
                    current_flows[fwd_flow].new_packet(packet)

            # Check if bwd flow
            elif bwd_flow in current_flows.keys():
                bwd_count += 1
                
                # Check for Reset or Fin flag
                if "TCP" in packet and (packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1):
                    current_flows[bwd_flow].new_packet(packet)
                    del(current_flows[bwd_flow])
                    del_flow_count += 1
                    
                # Update packet
                else:
                    current_flows[bwd_flow].new_packet(packet)

            # Make new flow
            else:
                flow = FlowSession(packet)
                current_flows[fwd_flow] = flow
            
            # Stats
            print(str(len(current_flows)),'\t\t', str(fwd_count), '\t\t', str(bwd_count), '\t\t', str(del_flow_count))
            for flow_id, flow_class in current_flows.items():
                print(flow_class.get_src_ip(),'\t\t', timestamp - flow_class.get_packet_last_timestamp(), '\t\t', flow_class.get_timestamp(), flow_class.get_syn_count())
            print('\n')

        # Check all flows for timeouts
        for flow_id, flow_class in current_flows.copy().items():
            if timestamp - flow_class.get_packet_last_timestamp() >= timeout:
                del(current_flows[flow_id])
                del_flow_count += 1

    except Exception as error:
        print(error)