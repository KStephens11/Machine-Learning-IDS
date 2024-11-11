import pyshark
import logging
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
            
            

for packet in capture:
    
    timestamp = packet.sniff_time.timestamp()
    
    handle_packet(packet)
    
    list_flows()

    check_flow_timeout()
    