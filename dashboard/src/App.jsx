import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar          from './components/Sidebar';
import Overview         from './pages/Overview';
import ScanTool         from './pages/ScanTool';
import DetectionHistory from './pages/DetectionHistory';
import Analytics        from './pages/Analytics';
import Lists            from './pages/Lists';
import Feedback         from './pages/Feedback';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Sidebar />
        <main className="main-scroll">
          <Routes>
            <Route path="/"          element={<Overview />} />
            <Route path="/scan"      element={<ScanTool />} />
            <Route path="/history"   element={<DetectionHistory />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/lists"     element={<Lists />} />
            <Route path="/feedback"  element={<Feedback />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
