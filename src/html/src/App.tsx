import { Route, Routes } from 'react-router-dom';
import './App.css'

import Navbar from "./components/Navbar";

import Flows from './components/Flows';
import Devices from './components/Devices';
import Statistics from './components/Statistics';
import Settings from './components/Settings';


function App()
{
  return <div className='App'>
    
    <Navbar/>
    
    <div className='Content'>

        <Routes>
          <Route path='/flows' element={<Flows />} />
          <Route path='/devices' element={<Devices />} />
          <Route path='/statistics' element={<Statistics />} />
          <Route path='/settings' element={<Settings />} />
        </Routes>

    </div>

  </div>
}

export default App;