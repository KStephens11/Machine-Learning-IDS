import packet_capture
from manager import FlowManager
from traffic_analyzer import TrafficAnalyzer
import logging
import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

class Device(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    attack_type: str
    probability: float


app = FastAPI()

origins = [
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

flow_db = {"flows": []}

@app.get("/api/flows")
def get_flows():
    return (flow_db)


logging.basicConfig(
    filename="logs/main.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def main_app():
    print("Starting Capture...")
    capture = packet_capture.start("192.168.0.108")
    flow_manager = FlowManager(56.3, 10)
    traffic_analyzer = TrafficAnalyzer("model/rf.pkl", "model/le.pkl")
    print("Capturing Packets...")

    f = open("logs/output_data.csv", "w+")
    f.write("dst_port,proto,flow_duration_ms,tot_fwd_pkts,tot_bwd_pkts,total_fwd_pkt_len,total_bwd_pkt_len,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,flow_byts_s,flow_pkts_s,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flag,bwd_psh_flag,fwd_urg_flag,bwd_urg_flag,fwd_header_len,bwd_header_len,flow_fwd_pkts_s,flow_bwd_pkts_s,pkt_len_min,pkt_len_max,pkt_len_mean,pkt_len_std,pkt_len_var,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,pkt_size_avg,fwd_seg_size_avg,bwd_seg_size_avg,subflow_fwd_pkts,subflow_fwd_bytes,subflow_bwd_pkts,subflow_bwd_bytes,init_fwd_win_bytes,init_bwd_win_bytes,fwd_act_data_pkts,fwd_seg_size_min,active_mean,active_std,active_max,active_min,idle_mean,idle_std,idle_max,idle_min")
    f.write('\n')
    f.close()

    try:
        while True:
            if packet_capture.has_next():
                packet = packet_capture.get_packet()
                flow_manager.handle_packet(packet)
                flow_manager.check_flow_timeout()
                flow_manager.list_flows()

                flow_data = flow_manager.get_flow_data()
                if flow_data:
                    result = traffic_analyzer.get_prediction(flow_data)
                    #logging.info(result)
                    flow_db["flows"].append(Device(src_ip=flow_data[0], dst_ip=flow_data[1], src_port=flow_data[2], dst_port=flow_data[3], protocol=flow_data[4], attack_type="placeholder", probability=result[:, 1].item()*100))

    except KeyboardInterrupt:
        print("\nExiting...")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":

    thread = threading.Thread(target=main_app)
    thread.start()

    uvicorn.run(app, host="0.0.0.0", port=8000)
