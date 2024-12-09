import logging
from session import FlowSession

logging.basicConfig(
    filename="manager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class FlowManager:
    def __init__(self, timeout):
        self.current_flows = {}
        self.deleted_flows_count = 0
        self.timeout = timeout
        self.timestamp = 0
    
    def handle_packet(self, packet, timestamp):
        # Dont check non IP packets
        if "IP" not in packet:
            return
        
        if "TCP" not in packet and "UDP" not in packet:
            return
        
        self.timestamp = timestamp
        
        flow_key, flow_direction = self.get_flow_key_and_direction(packet)

        # Check if flow already exists, else create new session
        if flow_key in self.current_flows:
            self.process_existing_flow(packet, flow_key, flow_direction)
        else:
            self.create_flow(packet, flow_key)
    
    def get_flow_key_and_direction(self, packet):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        proto_num = packet.ip.proto
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        fwd_flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
        bwd_flow_id = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"

        # Return flow key and direction
        if fwd_flow_id in self.current_flows:
            return fwd_flow_id, "FWD"
        return bwd_flow_id, "BWD"

    def process_existing_flow(self, packet, flow_key, flow_direction):
        flow = self.current_flows[flow_key]

        # Handle FIN or RST flags in TCP packets
        if packet.transport_layer == "TCP":
            self.handle_tcp_flags(packet, flow_key, flow, flow_direction)
        else:
            flow.new_packet(packet, flow_direction)

    def handle_tcp_flags(self, packet, flow_key, flow, flow_direction):
        if packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1:
            flow.new_packet(packet, flow_direction)
            self.delete_flow(flow_key, flow)
            logging.info(f"Deleted flow {flow_key}, FIN/RST flag")
        else:
            flow.new_packet(packet, flow_direction)

    def create_flow(self, packet, flow_key):
        self.current_flows[flow_key] = FlowSession(packet, "FWD")
        self.current_flows[flow_key].new_packet(packet, "FWD")
        logging.info(f"Created flow {flow_key}")
        
    def delete_flow(self, flow_key, flow):
        final_data = flow.get_final_data()
        logging.info(f"DURATION {final_data}")
        del self.current_flows[flow_key]
        self.deleted_flows_count += 1

    def list_flows(self):
        print(f"Current Flows: {len(self.current_flows)}  Deleted Flows: {self.deleted_flows_count}")
        print(f"{'Src IP':<20} {'Dst IP':<20} {'Src Port':<10} {'Dst Port':<10} {'Last Seen':<20}")
        for flow in self.current_flows.values():
            last_seen = self.timestamp - flow.get_packet_last_seen()
            print(f"{flow.get_src_ip():<20} {flow.get_dst_ip():<20} {flow.get_src_port():<10} {flow.get_dst_port():<10} {last_seen:<20}")
        print('\n')

    def check_flow_timeout(self):
        for flow_key, flow in list(self.current_flows.items()):
            time_since_last_seen = self.timestamp - flow.get_packet_last_seen()
            if time_since_last_seen >= self.timeout:
                self.delete_flow(flow_key, flow)
                logging.info(f"Deleted flow {flow_key}, TIMEOUT")
