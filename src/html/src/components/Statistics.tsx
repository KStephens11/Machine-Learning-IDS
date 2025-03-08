
import { Bar, Line } from "react-chartjs-2";
import { Fragment } from "react/jsx-runtime";
import 'chart.js/auto'; //important
import { useEffect, useState } from "react";
import api from "./api";


// Num of Attacks over time
// traffic volume (bytes/s)
// CPU Usage, Mem Usage

function Statistics() {   
    interface StatsItem {
        timestamp: string;
        num_active_flows: number;
        num_deleted_flows: number;
        num_packets: number;
        num_ddos: number;
        num_bruteforce: number;
        num_botnet: number;
        num_webattack: number;
        num_infultration: number;
    }

    const [statsList , setStatsList] = useState<StatsItem[]>([]);

    const fetchStats = async () => {
        try {
            const response = await api.get<StatsItem[]>("/api/stats");
            setStatsList(response.data);
        } catch (error) {
            console.error("Error fetching flows:", error);
        }
    };

    useEffect(() => {
        fetchStats();

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

    const num_ddos = statsList.map((item) => item.num_ddos);
    const num_bruteforce = statsList.map((item) => item.num_bruteforce);
    const num_botnet = statsList.map((item) => item.num_botnet);
    const num_webattack = statsList.map((item) => item.num_webattack);
    const num_infiltration = statsList.map((item) => item.num_infultration);


    return (
        <Fragment>
            <div className="container">
                <h1 className="text-center my-3">Statistics</h1>

                <div className="dataCard card mb-4 px-2" id="device-card">

                    <Bar data={{
                            datasets: [
                                {
                                    label: "DDOS",
                                    data: num_ddos,
                                },

                                {
                                    label: "Bruteforce",
                                    data: num_bruteforce,
                                },

                                {
                                    label: "Botnet",
                                    data: num_botnet,
                                },

                                {
                                    label: "Web Attack",
                                    data: num_webattack,
                                },

                                {
                                    label: "Infiltration",
                                    data: num_infiltration,
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
                                {
                                    label: "Deleted Flows",
                                    data: deleted_flows,
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

            </div>
        </Fragment>
    )


}

export default Statistics;