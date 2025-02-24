import { useEffect, useState } from "react";
import { Fragment } from "react/jsx-runtime";
import api from "./api";

function Devices() {

    interface DeviceItem {
        ip: string;
        tot_fwd_pkts: number;
        tot_bwd_pkts: number;
        good_flows: number;
        bad_flows: number;
        total_flows: string;
    }

    const [deviceList, setDeviceList] = useState<DeviceItem[]>([]);
    const [selectedIndex, setSelectedIndex] = useState(-1);

    // Fetch data from the API
    const fetchDevices = async () => {
        try {
            const response = await api.get("/api/devices");
            const devices = response.data;

            // Convert the response object into an array of devices
            const deviceArray = Object.keys(devices).map((key) => {
                return {
                    ip: key,
                    tot_fwd_pkts: devices[key].tot_fwd_pkts,
                    tot_bwd_pkts: devices[key].tot_bwd_pkts,
                    good_flows: devices[key].good_flows,
                    bad_flows: devices[key].bad_flows,
                    total_flows: devices[key].total_flows,
                };
            });

            setDeviceList(deviceArray);
        } catch (error) {
            console.error("Error fetching flows:", error);
        }
    };

    useEffect(() => {
        fetchDevices();

        const interval = setInterval(() => {
            fetchDevices();
        }, 5000);

        // Clean up interval
        return () => clearInterval(interval);
    }, []);
    return (
        <Fragment>
            <div className="container">
                <h1 className="text-center my-4">Devices</h1>
                <ul className ="list-group">
                {
                    deviceList.map((device, index) => 
                        (
                            <li className={selectedIndex === index ? "list-group-item active rounded" : "list-group-item rounded"}
                                key={device.ip}
                                onClick={() => {setSelectedIndex(index);}}
                            >
                                <div className="row g-0" style={{marginLeft: 10}}>
                                    <div className="col-4">
                                        <small className="text-muted">IP Address</small>
                                    </div>
                                    <div className="col-2">
                                        <small className="text-muted">FWD Packets</small>
                                    </div>
                                    <div className="col-2">
                                        <small className="text-muted">BWD Packets</small>
                                    </div>
                                    <div className="col-1">
                                        <small className="text-muted">Benign Flows</small>
                                    </div>
                                    <div className="col-1">
                                        <small className="text-muted">Strange Flows</small>
                                    </div>
                                    <div className="col-1">
                                        <small className="text-muted">Total Flows</small>
                                    </div>
                                </div>
                                <div style={{marginLeft: 10}} className="row g-0">
                                    <div className="col-4">
                                        {device.ip}
                                    </div>
                                    <div className="col-2">
                                        {device.tot_fwd_pkts}
                                    </div>
                                    <div className="col-2">
                                        {device.tot_bwd_pkts}
                                    </div>
                                    <div className="col-1">
                                        {device.good_flows}
                                    </div>
                                    <div className="col-1">
                                        {device.bad_flows}
                                    </div>
                                    <div className="col-1">
                                        {device.total_flows}
                                    </div>
                                      
                                </div>
                            </li>
                        )
                    )   
                }

                </ul>

            </div>
        </Fragment>
    )

}

export default Devices;