import React, { useState } from 'react';
import Landing from './pages/Landing';
import Scanning from './pages/Scanning';
import Results from './pages/Results';
import BackgroundGrid from './components/BackgroundGrid';

export default function App() {
  const [page, setPage] = useState('landing'); // 'landing' | 'scanning' | 'results'
  const [scanUrl, setScanUrl] = useState('');
  const [checkResults, setCheckResults] = useState([]);
  const [finalData, setFinalData] = useState(null);

  const startScan = (url) => {
    setScanUrl(url);
    setCheckResults([]);
    setFinalData(null);
    setPage('scanning');
  };

  const onScanComplete = (results, final) => {
    setCheckResults(results);
    setFinalData(final);
    setPage('results');
  };

  const resetScan = () => {
    setPage('landing');
    setScanUrl('');
    setCheckResults([]);
    setFinalData(null);
  };

  return (
    <>
      {/* Global animated background */}
      <BackgroundGrid />
      <div className="grid-bg" style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none' }} />


      {/* Pages rendered in a relative z-index container */}
      <div style={{ position: 'relative', zIndex: 2 }}>
        {page === 'landing' && <Landing onStart={startScan} />}
        {page === 'scanning' && (
          <Scanning url={scanUrl} onComplete={onScanComplete} onCancel={resetScan} />
        )}
        {page === 'results' && (
          <Results results={checkResults} finalData={finalData} url={scanUrl} onRescan={resetScan} />
        )}
      </div>
    </>
  );
}

