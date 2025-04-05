
import { Bar, Line } from "react-chartjs-2";
import { Fragment } from "react/jsx-runtime";
import 'chart.js/auto'; //important
import { useEffect, useState } from "react";
import api from "./api";


function Statistics() {   
    interface StatsItem {
        timestamp: string;
        num_active_flows: number;
        num_deleted_flows: number;
        num_packets: number;
        num_brute_ftp: number;
        num_brute_ssh: number;
        num_ddos_http: number;
        num_ddos_tcp_udp: number;
        num_dos_slow_http: number;
        cpu_usage: number;
        memory_usage: number;
    }

    const [statsList , setStatsList] = useState<StatsItem[]>([]);

    const fetchStats = async () => {
        try {
            const response = await api.get<StatsItem[]>("/api/stats");
            setStatsList(response.data.slice(-50));
        } catch (error) {
            console.error("Error fetching flows:", error);
        }
    };

    useEffect(() => {
        fetchStats();
            console.log("FETCH")
            const interval = setInterval(() => {
                fetchStats();
            }, 5000);

            // Clean up interval
            return () => clearInterval(interval);
        }, []);

    
    const labels = statsList.map((item) => new Date(parseFloat(item.timestamp) * 1000).toLocaleTimeString());
    const active_flows = statsList.map((item) => item.num_active_flows);
    const deleted_flows = statsList.map((item) => item.num_deleted_flows);
    const num_packets = statsList.map((item) => item.num_packets);
    const cpu_usage = statsList.map((item) => item.cpu_usage);
    const memory_usage = statsList.map((item) => item.memory_usage);

    const num_brute_ftp = statsList.length > 0 ? statsList[statsList.length - 1].num_brute_ftp : null;
    const num_brute_ssh = statsList.length > 0 ? statsList[statsList.length - 1].num_brute_ssh : null;
    const num_ddos_http = statsList.length > 0 ? statsList[statsList.length - 1].num_ddos_http : null;
    const num_ddos_tcp_udp = statsList.length > 0 ? statsList[statsList.length - 1].num_ddos_tcp_udp : null;
    const num_dos_slow_http = statsList.length > 0 ? statsList[statsList.length - 1].num_dos_slow_http : null;


    return (
        <Fragment>
            <div className="container">
                <h1 className="text-center my-3">Statistics</h1>

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Bar data={{
                            labels: ["DDOS HTTP", "DDOS TCP/UDP", "DOS HTTP", "BRUTEFORCE SSH", "BRUTEFORCE FTP"], 
                            datasets: [
                                {
                                    label: "Number of Attacks",
                                    data: [num_ddos_http, num_ddos_tcp_udp, num_dos_slow_http, num_brute_ssh, num_brute_ftp],
                                },
                            ],
                    }}/>

                </div>

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Line data={{
                            labels: labels,
                            datasets: [
                                {
                                    label: "Active Flows",
                                    data: active_flows,
                                },
                            ],
                    }}/>

                </div>
                
                

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Line data={{
                            labels: labels,
                            datasets: [
                                {
                                    label: "Packets",
                                    data: num_packets,
                                },
                            ],
                    }}/>

                </div>

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Line data={{
                            labels: labels,
                            datasets: [
                                {
                                    label: "CPU Usage",
                                    data: cpu_usage,
                                },
                            ],
                    }}/>

                </div>

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Line data={{
                            labels: labels,
                            datasets: [
                                {
                                    label: "Memory Usage",
                                    data: memory_usage,
                                },
                            ],
                    }}/>

                </div>

            </div>
        </Fragment>
    )


}

export default Statistics;