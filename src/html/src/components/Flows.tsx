import { useEffect, useState } from "react";
import { Fragment } from "react/jsx-runtime";
import '../App.css';
import api from "./api";

function Flows() {

    interface DeviceItem {
        src_ip: string;
        dst_ip: string;
        src_port: number;
        dst_port: number;
        protocol: number;
        attack_type: string;
        probability: number;
    }

    const [flowList, setFlowList] = useState< DeviceItem[] > ([]);

    const fetchFlows = async () => {
        try {
            const response = await api.get<{flows: DeviceItem[]}> ("/api/flows");
            setFlowList(response.data.flows);
        } catch (error) {
            console.error("Error fetching devices:", error);
        }
    };

    useEffect(() => {

        fetchFlows();

        const interval = setInterval(() => {
            fetchFlows();
        }, 5000);
        //Clean up interval
        return () => clearInterval(interval);

    }, []);

    const [selectedIndex, setSelectedIndex] = useState(-1);

    return (
        <Fragment>
            <div className="container">
                <h1 className="text-center my-4">Flows</h1>
                <table className="table table-bordered table-hover">
                    <thead className="thead-dark">
                        <tr>
                            <th>Index</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Source Port</th>
                            <th>Destination Port</th>
                            <th>Protocol</th>
                            <th>Traffic Type</th>
                            <th>Probability</th>
                        </tr>
                    </thead>
                    <tbody>
                        {flowList.map((flow, index) => (
                            <tr 
                                key={index++} 
                                className={selectedIndex === index ? 'table-primary' : ''} 
                                onClick={() => setSelectedIndex(index)}
                                style={{ cursor: 'pointer' }}
                            >
                                <td>{index++}</td>
                                <td>{flow.src_ip}</td>
                                <td>{flow.dst_ip}</td>
                                <td>{flow.src_port}</td>
                                <td>{flow.dst_port}</td>
                                <td>{flow.protocol}</td>
                                <td>{flow.attack_type}</td>
                                <td>{flow.probability}</td>

                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </Fragment>
    );
}

export default Flows;
