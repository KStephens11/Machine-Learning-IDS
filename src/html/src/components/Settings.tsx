import { Fragment } from "react/jsx-runtime";
import '../App.css'
import api from "./api";
import { useEffect, useState } from "react";

function Settings() {   

    interface SettingsItem {
        capture_interface: string;
        flow_timeout: number;
        subflow_timeout: number;
        model: string;
        clear_db: boolean;
        filtered_addresses: string[];
        attack_threshold: number;
    }

    const [interfaceAddress, setInterfaceAddress] = useState<string>('');
    const [flowTimeout, setFlowTimeout] = useState<number>(0);
    const [subflowTimeout, setSubflowTimeout] = useState<number>(0);
    const [attackThreshold, setAttackThreshold] = useState<number>(0);
    const [model, setModel] = useState<string>('');
    const [clearDb, setClearDb] = useState<boolean>(false);
    const [filteredAddresses, setFilteredAddresses] = useState<string[]>([]);


    // Fetch data from the API
    const fetchSettings = async () => {
        try {
            const response = await api.get<SettingsItem>("/api/settings");
            setInterfaceAddress(response.data.capture_interface);
            setFlowTimeout(response.data.flow_timeout);
            setSubflowTimeout(response.data.subflow_timeout);
            setAttackThreshold(response.data.attack_threshold);
            setModel(response.data.model);
            setClearDb(response.data.clear_db);
            setFilteredAddresses(response.data.filtered_addresses);

        } catch (error) {
            console.error("Error fetching settings:", error);
        }
    };

    const postSettings = async () => {
        try {

            const updatedSettings: SettingsItem = {
                capture_interface: interfaceAddress,
                flow_timeout: flowTimeout,
                subflow_timeout: subflowTimeout,
                attack_threshold: attackThreshold,
                model: model,
                clear_db: clearDb,
                filtered_addresses: filteredAddresses
            };

            console.log(updatedSettings)

            await api.post("/api/settings", updatedSettings)

        } catch (error) {
            console.error("Error posting settings:", error);
        }
    }



    useEffect(() => {
        fetchSettings();
    }, []);


    return (
        <Fragment >
            <h1 className="text-center my-4">Settings</h1>

            <div className="container">
                <div className="card py-0 px-0" id="device-card">

                    <div className="input-group mb-3" >
                        <div className="input-group-prepend mt-3">
                            <span className="input-group-text" id="settings-option-text" >Interface Address</span>
                        </div>
                        <input type="text" className="form-control mt-3" id="interface_address" placeholder={interfaceAddress} aria-describedby="basic-addon3" onChange={(e) => setInterfaceAddress(e.target.value)}/>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                            <span className="input-group-text" id="settings-option-text">Flow Timeout</span>
                        </div>
                        <input type="number" className="form-control" id="flow_timeout" placeholder={String(flowTimeout)} aria-describedby="basic-addon3" onChange={(e) => setFlowTimeout(Number(e.target.value))}/>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                            <span className="input-group-text" id="settings-option-text">Subflow Timeout</span>
                        </div>
                        <input type="number" className="form-control" id="subflow_timeout" placeholder={String(subflowTimeout)} aria-describedby="basic-addon3" onChange={(e) => setSubflowTimeout(Number(e.target.value))}/>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                            <span className="input-group-text" id="settings-option-text">Attack Flag Threshold</span>
                        </div>
                        <input type="number" className="form-control" id="interface_address" placeholder={String(attackThreshold)} aria-describedby="basic-addon3" onChange={(e) => setAttackThreshold(Number(e.target.value))}/>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                                <span className="input-group-text" id="settings-option-text">Machine Learning Model</span>
                            </div>
                        <select className="form-control" aria-label="Default select example" value={model} onChange={(e) => setModel(e.target.value)}>
                            <option value="random_forest">Random Forest</option>
                            <option value="xgboost">XGBoost</option>
                            <option value="logistic_regression">Logistic Regression</option>
                            <option value="k_means">K-means</option>
                            <option value="auto_encoder">Autoencoder</option>
                        </select>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                                <span className="input-group-text" id="settings-option-text">Clear Database</span>
                            </div>
                        <select className="form-control" aria-label="Default select example" value={String(clearDb)} onChange={(e) => setClearDb(e.target.value === "true")}>
                            <option value="false">False</option>
                            <option value="true">True</option>
                        </select>
                    </div>

                    <div className="input-group mb-3">
                        <div className="input-group-prepend">
                            <span className="input-group-text" id="settings-option-text">Filtered Addresses</span>
                        </div>
                        <input type="text" className="form-control" id="interface_address" placeholder={String(filteredAddresses)} aria-describedby="basic-addon3" onChange={(e) => setFilteredAddresses(e.target.value.split(","))}/>
                    </div>

                    <div className="input-group-button mb-3">
                        <div className="input-group-prepend">
                            <button type="button" className="btn btn-primary btn-lg" onClick={postSettings} >Save Settings</button>
                        </div>
                    </div>
                </div>
            </div>
        </Fragment>
    )


}

export default Settings;