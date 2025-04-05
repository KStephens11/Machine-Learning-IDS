import { Link } from 'react-router-dom';

const Navbar = () => {
    return (
        <div className='Navbar'>

            <h1>ML IDS</h1>

            <hr className="solid"></hr>

            <ul>

                <li>
                    <Link to='/flows'>Flows</Link>
                </li>

                <li>
                    <Link to='/devices'>Devices</Link>
                </li>

                <li>
                    <Link to='/Statistics'>Statistics</Link>
                </li>

                <li>
                    <Link to='/settings'>Settings</Link>
                </li>

            </ul>

        </div>
    )
}

export default Navbar