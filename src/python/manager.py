import logging
from session import FlowSession

logging.basicConfig(
    filename="logs/manager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class FlowManager:
    def __init__(self, timeout, subflow_timeout):
        self.current_flows = {}
        self.deleted_flows_count = 0
        self.timeout = timeout
        self.subflow_timeout = subflow_timeout
        self.timestamp = 0
        self.flow_data = []
    
    def handle_packet(self, packet):
        try:

            self.timestamp = packet.timestamp

            flow_key, flow_direction = self.get_flow_key_and_direction(packet)

            # Check if flow already exists, else create new session
            if flow_key in self.current_flows:
                self.process_existing_flow(packet, flow_key, flow_direction)
            else:
                self.create_flow(packet, flow_key)
        except Exception as e:
            print("Could not handle packet: " + str(e))
            exit()
    
    def get_flow_key_and_direction(self, packet):
        try:
            proto_num = packet.protocol
            src_ip = packet.src_ip
            dst_ip = packet.dst_ip
            src_port = packet.src_port
            dst_port = packet.dst_port

            fwd_flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
            bwd_flow_id = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"

            # Return flow key and direction
            if fwd_flow_id in self.current_flows:
                return fwd_flow_id, "FWD"
            else:
                return bwd_flow_id, "BWD"
        except Exception as e:
            print("Could not get flow_key and direction: " + str(e))
            exit()

    def process_existing_flow(self, packet, flow_key, flow_direction):
        try:
            flow = self.current_flows[flow_key]

            # Create subflow
            if (self.timestamp - flow.get_packet_last_seen()) >= self.subflow_timeout:
                flow.create_subflow(self.timestamp)

            # Handle FIN or RST flags in TCP packets
            if packet.protocol == 6:
                self.handle_tcp_flags(packet, flow_key, flow, flow_direction)
            else:
                flow.new_packet(packet, flow_direction)
        except Exception as e:
            print("Could not process existing flow: " + str(e))
            exit()

    def handle_tcp_flags(self, packet, flow_key, flow, flow_direction):
        try:
            if packet.fin_flag == 1 or packet.rst_flag == 1:
                flow.new_packet(packet, flow_direction)
                self.delete_flow(flow_key, flow)
            else:
                flow.new_packet(packet, flow_direction)
        except Exception as e:
            print("Could not handle tcp flags: " + str(e))
            exit()

    def create_flow(self, packet, flow_key):
        try:
            self.current_flows[flow_key] = FlowSession(packet)
            self.current_flows[flow_key].create_subflow(self.timestamp)
            self.current_flows[flow_key].new_packet(packet, "FWD")
            logging.info(f"Created flow {flow_key}")
        except Exception as e:
            print("Could not create new flow: " + str(e))
            exit()
        
    def delete_flow(self, flow_key, flow):
        try:
            self.flow_data.append(flow.get_final_data())
            del self.current_flows[flow_key]
            self.deleted_flows_count += 1
            logging.info(f"Deleted flow {flow_key}, FIN/RST flag")
        except Exception as e:
            print("Could not delete flow: " + str(e))
            exit()

    def list_flows(self):
        try:
            for flow in self.current_flows.values():
                last_seen = round(self.timestamp - flow.get_packet_last_seen())
                print(f"{flow.get_src_ip():<40} {flow.get_dst_ip():<40} {flow.get_src_port():<10} {flow.get_dst_port():<10} {last_seen:<10}")
            print(f"{'Src IP':<40} {'Dst IP':<40} {'Src Port':<10} {'Dst Port':<10} {'Last Seen':<20}")
            print(f"Current Flows: {len(self.current_flows)}  Deleted Flows: {self.deleted_flows_count}")
            print('\n')
        except Exception as e:
            print("Could not list flows: " + str(e))
            exit()

    def check_flow_timeout(self):
        try:
            for flow_key, flow in list(self.current_flows.items()):
                time_since_last_seen = self.timestamp - flow.get_packet_last_seen()
                time_since_start = self.timestamp - flow.get_timestamp()
                if time_since_last_seen >= self.timeout:
                    self.delete_flow(flow_key, flow)
                    logging.info(f"Deleted flow {flow_key}, TIMEOUT")
        except Exception as e:
            print("Could not check flow timeout: " + str(e))
            exit()

    def get_flow_data(self):
        try:
            if self.flow_data:
                flow_data = self.flow_data.pop()
            else:
                flow_data = None
            return flow_data
        except Exception as e:
            print("Could not get flow data: " + str(e))
            exit()