import pyshark
<<<<<<< HEAD
import logging
=======
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
from session import FlowSession
capture = pyshark.LiveCapture(interface='wlan0')

# CREATE LOG FILE, REVIEW RST FLAG, GET MORE DATA COLLECTED(ALL PREFERABLY)

logging.basicConfig(
    filename="ids.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

current_flows = {}
del_flow_count = 0
timeout = 70
timestamp = 0


def handle_packet(packet):
    global del_flow_count
    try:
        if "IP" not in packet:
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        proto_num = packet.ip.proto
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        # Define forward and backward flows
        fwd_flow_id = src_ip + "-" + dst_ip + "-" + src_port + "-" + dst_port + "-" + proto_num
        bwd_flow_id = dst_ip + "-" + src_ip + "-" + dst_port + "-" + src_port + "-" + proto_num

        # Select flow direction and check if it exists
        flow_direction, flow_key = ("FWD", fwd_flow_id) if fwd_flow_id in current_flows else ("BWD", bwd_flow_id)
        
        if flow_key in current_flows:
            # Handle Reset or Fin flag if packet is TCP
            if packet.transport_layer == "TCP":
                
                if packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1:
                                        
                    current_flows[flow_key].new_packet(packet, flow_direction)
                    
                    current_flows[flow_key].get_final_data()
                    
                    logging.info(f"DURATION {current_flows[flow_key].get_final_data()}")
                    
                    del current_flows[flow_key]
                    
                    del_flow_count += 1
                    
                    logging.info(f"Deleted flow {flow_key}, FIN/RST flag")
                
                else:
                    current_flows[flow_key].new_packet(packet, flow_direction)
        else:
            # Create a new flow if neither fwd nor bwd flows are found
            current_flows[fwd_flow_id] = FlowSession(packet, "FWD")
            current_flows[fwd_flow_id].new_packet(packet, "FWD")
            logging.info(f"Created flow {flow_key}")
            
    except Exception as error:
        print(error)


def list_flows():
    global del_flow_count
    print(f"Current Flows: {str(len(current_flows))}  Deleted Flows: {str(del_flow_count)}")
    
    print(f"{'Src IP':<20} {'Dst IP':<20} {'Last Seen':<15}")
    
    for flow_id, flow in current_flows.items():
        print(f"{str(flow.get_src_ip()):<20} {str(flow.get_dst_ip()):<20} {str(timestamp - flow.get_packet_last_seen()):<20}")
    print('\n')


def check_flow_timeout():
    global del_flow_count
    
    # Check all flows for timeouts
    for flow_key, flow in current_flows.copy().items():
        if (timestamp - flow.get_packet_last_seen()) >= timeout:
            
            current_flows[flow_key].get_final_data()
            
            logging.info(f"DURATION {current_flows[flow_key].get_final_data()}")
            
            print(current_flows[flow_key].get_final_data())
            
            del(current_flows[flow_key])
            del_flow_count += 1
            
            logging.info(f"Deleted flow {flow_key}, TIMEOUT")
            
            

current_flows = {}
bwd_count = 0
fwd_count = 0
del_flow_count = 0
timeout = 100
timestamp = 0

for packet in capture:
<<<<<<< HEAD
    
    timestamp = packet.sniff_time.timestamp()
    
    handle_packet(packet)
    
    list_flows()

    check_flow_timeout()
    

=======
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
>>>>>>> 8f0a3670b799a37474e07a59914466e516ed4c03
