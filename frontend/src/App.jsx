import React, { useState, useEffect } from 'react';
import Landing from './pages/Landing';
import Scanning from './pages/Scanning';
import Results from './pages/Results';
import Privacy from './pages/Privacy';
import Terms from './pages/Terms';
import BackgroundGrid from './components/BackgroundGrid';
import ConsentGate from './components/ConsentGate';
import ContactModal from './components/ContactModal';
import { API_BASE } from './config';

export default function App() {
  const [page, setPage] = useState('landing');
  const [scanUrl, setScanUrl] = useState('');
  const [checkResults, setCheckResults] = useState([]);
  const [finalData, setFinalData] = useState(null);
  const [prevScore, setPrevScore] = useState(null);
  const [contactOpen, setContactOpen] = useState(false);
  const [consentAccepted, setConsentAccepted] = useState(() => {
    try {
      return localStorage.getItem('ss-consent-accepted') === 'true';
    } catch {
      return false;
    }
  });
  const [dark, setDark] = useState(() => {
    try {
      const stored = localStorage.getItem('ss-theme');
      if (stored) return stored === 'dark';
    } catch {}
    return true;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    try {
      localStorage.setItem('ss-theme', dark ? 'dark' : 'light');
    } catch {}
  }, [dark]);

  useEffect(() => {
    const path = window.location.pathname;
    const match = path.match(/^\/report\/([a-f0-9-]+)/i);
    if (match) {
      const uuid = match[1];
      fetch(`${API_BASE}/reports/${uuid}`)
        .then((res) => {
          if (!res.ok) throw new Error('Report not found or expired');
          return res.json();
        })
        .then((report) => {
          setScanUrl(report.url);
          setCheckResults(report.results);
          setFinalData(report);
          setPrevScore(null);
          setPage('results');
        })
        .catch((err) => {
          console.error('Error loading shared report:', err);
          window.history.replaceState({}, document.title, '/');
        });
    }
  }, []);

  const startScan = (url) => {
    if (finalData) {
      setPrevScore(finalData.score);
    } else {
      setPrevScore(null);
    }
    setScanUrl(url);
    setCheckResults([]);
    setFinalData(null);
    setPage('scanning');
  };

  const onScanComplete = (results, final) => {
    setCheckResults(results);
    setFinalData({ ...final, results });
    setPage('results');
  };

  const resetScan = () => {
    setPage('landing');
    setScanUrl('');
    setCheckResults([]);
    setFinalData(null);
  };

  const handleNavigate = (targetPage) => {
    setPage(targetPage);
  };

  const handleAcceptConsent = () => {
    try {
      localStorage.setItem('ss-consent-accepted', 'true');
    } catch {}
    setConsentAccepted(true);
  };

  return (
    <>
      <BackgroundGrid dark={dark} />
      <div className="grid-bg" style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none' }} />
      <div style={{ position: 'relative', zIndex: 2 }}>
        {!consentAccepted ? (
          <ConsentGate onAccept={handleAcceptConsent} dark={dark} />
        ) : (
          <div key={page} className="page-enter">
            {page === 'landing' && (
              <Landing onStart={startScan} dark={dark} onToggleDark={() => setDark((d) => !d)} onNavigate={handleNavigate} onContactClick={() => setContactOpen(true)} />
            )}
            {page === 'scanning' && (
              <Scanning url={scanUrl} onComplete={onScanComplete} onCancel={resetScan} dark={dark} onToggleDark={() => setDark((d) => !d)} onContactClick={() => setContactOpen(true)} />
            )}
            {page === 'results' && (
              <Results
                results={checkResults}
                finalData={finalData}
                url={scanUrl}
                onRescan={resetScan}
                dark={dark}
                onToggleDark={() => setDark((d) => !d)}
                prevScore={prevScore}
                onContactClick={() => setContactOpen(true)}
              />
            )}
            {page === 'privacy' && <Privacy onBack={resetScan} onContactClick={() => setContactOpen(true)} />}
            {page === 'terms' && <Terms onBack={resetScan} onContactClick={() => setContactOpen(true)} />}
          </div>
        )}
      </div>
      {contactOpen && <ContactModal onClose={() => setContactOpen(false)} />}
    </>
  );
}
