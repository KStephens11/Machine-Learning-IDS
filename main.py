import pyshark
from manager import FlowManager

def main():
    capture = pyshark.LiveCapture(interface='wlan0')
    flow_manager = FlowManager(timeout=70)

    for packet in capture:
        flow_manager.update_timestamp(packet.sniff_time.timestamp())
        flow_manager.handle_packet(packet)
        flow_manager.list_flows()
        flow_manager.check_flow_timeout()

if __name__ == "__main__":
    main()


#TODO
# ADD ALL DATA TO COLLECT
# CHECK FLOW DURATION, COMING UP 0 ALOT, MAY BE BROKE
# CHECK OTHER STATS TO VERIFY