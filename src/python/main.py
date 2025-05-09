import packet_capture
from manager import FlowManager
from traffic_analyzer import TrafficAnalyzer
import logging
import threading 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import time
import psutil


logging.basicConfig(
    filename="logs/main.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class Flow(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    attack_type: str
    probability: float

class Stats(BaseModel):
    timestamp: str
    num_active_flows: int
    num_deleted_flows: int
    num_packets: int
    num_brute_ftp: int
    num_brute_ssh: int
    num_ddos_http: int
    num_ddos_tcp_udp: int
    num_dos_slow_http: int

    memory_usage: float
    cpu_usage: float

class Settings(BaseModel):
    capture_interface: str
    flow_timeout: int
    subflow_timeout: int
    model: str
    clear_db: bool
    attack_threshold: int

app = FastAPI()

stop_event = threading.Event()
thread = None

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
overview_db = []
flow_db = []
device_db = dict()
stats_db = []
settings = {
    "capture_interface": "192.168.10.1",
    "flow_timeout": 300,
    "subflow_timeout": 10,
    "model": "random_forest",
    "clear_db": False,
    "attack_threshold": 60
}

@app.get("/api/flows")
def get_flows():
    return (flow_db)

@app.get("/api/devices")
def get_devices():
    return (device_db)

@app.get("/api/stats")
def get_devices():
    return (stats_db)

@app.get("/api/settings")
def get_settings():
    return (settings)

@app.post("/api/settings")
def set_settings(setting: Settings):
    global thread, flow_db, device_db

    # Update Settings
    settings.update(setting)

    # Check for clear DB
    if settings["clear_db"] == True:
        flow_db = []
        device_db = {}
        stats_db = []
        num_attacks_types = {
            "BRUTEFORCE-PATATOR-FTP": 0,
            "BRUTEFORCE-PATATOR-SSH": 0,
            "DDOS-LOIC-TCP/UDP": 0,
            "DDOS-LOIC-HTTP": 0,
            "DOS-SLOW-HTTP-TEST": 0
        }

    # Stop Thread
    stop_event.set()
    thread.join()

    # Restart Thread
    thread = threading.Thread(target=main_app)
    stop_event.clear()
    thread.start()

num_attacks_types = {
    "BRUTEFORCE-PATATOR-FTP": 0,
    "BRUTEFORCE-PATATOR-SSH": 0,
    "DDOS-LOIC-TCP/UDP": 0,
    "DDOS-LOIC-HTTP": 0,
    "DOS-SLOW-HTTP-TEST": 0
}

def main_app():
    # Setup
    print("Starting Capture...")
    capture = packet_capture.start(settings["capture_interface"])
    flow_manager = FlowManager(settings["flow_timeout"], settings["subflow_timeout"])
    traffic_analyzer = TrafficAnalyzer("model/" + settings["model"] + "/model.pkl")
    print("Capturing Packets...")

    # Create output CSV
    f = open("logs/output_data.csv", "w+")
    f.write("src_ip,dst_ip,src_port,dst_port,proto,flow_duration_ms,tot_fwd_pkts,tot_bwd_pkts,total_fwd_pkt_len,total_bwd_pkt_len,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,flow_byts_s,flow_pkts_s,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flag,bwd_psh_flag,fwd_urg_flag,bwd_urg_flag,fwd_header_len,bwd_header_len,flow_fwd_pkts_s,flow_bwd_pkts_s,pkt_len_min,pkt_len_max,pkt_len_mean,pkt_len_std,pkt_len_var,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,pkt_size_avg,fwd_seg_size_avg,bwd_seg_size_avg,subflow_fwd_pkts,subflow_fwd_bytes,subflow_bwd_pkts,subflow_bwd_bytes,init_fwd_win_bytes,init_bwd_win_bytes,fwd_act_data_pkts,fwd_seg_size_min,active_mean,active_std,active_max,active_min,idle_mean,idle_std,idle_max,idle_min")
    f.write('\n')
    f.close()

    timer = time.time()

    # Capture
    try:
        while not stop_event.is_set():

            if time.time() >= timer + 10:
                timer = time.time()
                try:
                    global stats_db
                    stats_db.append(Stats(timestamp=str(time.time()), num_active_flows=len(flow_manager.current_flows), num_deleted_flows=flow_manager.deleted_flows_count, num_packets=flow_manager.packet_count, num_brute_ftp=num_attacks_types["BRUTEFORCE-PATATOR-FTP"], num_brute_ssh=num_attacks_types["BRUTEFORCE-PATATOR-SSH"], num_ddos_http=num_attacks_types["DDOS-LOIC-HTTP"], num_ddos_tcp_udp=num_attacks_types["DDOS-LOIC-TCP/UDP"], num_dos_slow_http=num_attacks_types["DOS-SLOW-HTTP-TEST"], memory_usage=psutil.cpu_percent(interval=None), cpu_usage=psutil.virtual_memory().percent))
                    stats_db = stats_db[-50:]
                except Exception as e:
                    print("Could not append to stats_db:", e)

            while packet_capture.has_next():

                packet = packet_capture.get_packet()

                flow_manager.handle_packet(packet)
                flow_manager.check_flow_timeout()
                flow_manager.list_flows()

                flow_data = flow_manager.get_flow_data()

                if flow_data:

                    label, result = traffic_analyzer.get_prediction(flow_data)
                    
                    result_val = result*100

                    ip = flow_data["src_ip"]

                    try:
                        flow_db.append(Flow(src_ip=ip, dst_ip=flow_data["dst_ip"], src_port=flow_data["src_port"], dst_port=flow_data["dst_port"], protocol=flow_data["proto"], attack_type=label, probability=result_val))
                    except Exception as e:
                        print("Could not append to flow_db:", e)

                    if result_val >= settings["attack_threshold"] and label != "Benign":
                        good_flow = 0
                        bad_flow = 1
                        num_attacks_types[label] += 1
                    else:
                        good_flow = 1
                        bad_flow = 0

                    if ip not in device_db:
                        device_db[ip] = {
                            "tot_fwd_pkts": flow_data["tot_fwd_pkts"],
                            "tot_bwd_pkts": flow_data["tot_bwd_pkts"],
                            "good_flows": good_flow,
                            "bad_flows": bad_flow,
                            "total_flows": 1
                        }
                    else:
                        device_db[ip]["tot_fwd_pkts"] += flow_data["tot_fwd_pkts"]
                        device_db[ip]["tot_bwd_pkts"] += flow_data["tot_bwd_pkts"]
                        device_db[ip]["good_flows"] += good_flow
                        device_db[ip]["bad_flows"] += bad_flow
                        device_db[ip]["total_flows"] += 1

    except KeyboardInterrupt:
        print("\nExiting...")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":

    thread = threading.Thread(target=main_app)

    thread.start()

    uvicorn.run(app, host="0.0.0.0", port=8000)
