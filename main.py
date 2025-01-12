import pyshark
from manager import FlowManager
from traffic_analyzer import TrafficAnalyzer
import logging

logging.basicConfig(
    filename="main.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

if __name__ == "__main__":
    print("Starting Capture...")
    capture = pyshark.LiveCapture(interface='enp4s0')
    flow_manager = FlowManager(30, 10)
    traffic_analyzer = TrafficAnalyzer("model/rf.pkl", "model/le.pkl")
    print("Capturing Packets...")
    try:
        for packet in capture:
                flow_manager.handle_packet(packet, packet.sniff_time.timestamp())
                flow_manager.check_flow_timeout()
                #flow_manager.list_flows()

                flow_data = flow_manager.get_flow_data()
                if flow_data:
                    for flow in flow_data:
                        result = traffic_analyzer.get_prediction(flow)
                        flow_data.remove(flow)
                        logging.info(result)
                        print(result)


    except KeyboardInterrupt:
        print("\nExiting...")
        # Check all current flows

    except Exception as e:
        print(f"Error: {e}")
