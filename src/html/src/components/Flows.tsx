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

    const [flowList, setFlowList] = useState<DeviceItem[]>([]);
    const [selectedIndex, setSelectedIndex] = useState(-1);
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage] = useState(17);

    // Fetch data from the API
    const fetchFlows = async () => {
        try {
            const response = await api.get<{ flows: DeviceItem[] }>("/api/flows");
            setFlowList(response.data.flows);
        } catch (error) {
            console.error("Error fetching flows:", error);
        }
    };

    useEffect(() => {
        fetchFlows();

        const interval = setInterval(() => {
            fetchFlows();
        }, 5000);

        // Clean up interval
        return () => clearInterval(interval);
    }, []);

    // Get the current pages data
    const indexOfLastItem = currentPage * itemsPerPage;
    const indexOfFirstItem = indexOfLastItem - itemsPerPage;
    const currentItems = flowList.slice(indexOfFirstItem, indexOfLastItem);

    // Change page
    const paginate = (pageNumber: number) => {
        setCurrentPage(pageNumber);
        setSelectedIndex(-1);
    }

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
                        {currentItems.map((flow, index) => (
                            <tr
                                key={index + indexOfFirstItem}
                                className={selectedIndex === index ? 'table-primary' : ''}
                                onClick={() => setSelectedIndex(index)}
                                style={{ cursor: 'pointer' }}
                            >
                                <td>{index + 1 + indexOfFirstItem}</td>
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

                {/* Pagination Controls */}
                <nav aria-label="Page navigation">
                    <ul className="pagination justify-content-center">
                        <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
                            <button className="page-link" onClick={() => paginate(1)}>First</button>
                        </li>
                        <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
                            <button className="page-link" onClick={() => paginate(currentPage - 1)}>Previous</button>
                        </li>
                        <li className={`page-item ${currentPage === Math.ceil(flowList.length / itemsPerPage) ? 'disabled' : ''}`}>
                            <button className="page-link" onClick={() => paginate(currentPage + 1)}>Next</button>
                        </li>
                        <li className={`page-item ${currentPage === Math.ceil(flowList.length / itemsPerPage) ? 'disabled' : ''}`}>
                            <button className="page-link" onClick={() => paginate(Math.ceil(flowList.length / itemsPerPage))}>Last</button>
                        </li>
                    </ul>
                    <p className="pagination justify-content-center" style={{fontSize: 16, margin: 10}}>Page: {currentPage}</p>
                </nav>

                

            </div>
        </Fragment>
    );
}

export default Flows;
