import { useState, useCallback } from 'react';
import {
  initSession,
  makePurchase,
  getClientId,
} from './services/session';
import type {
  SessionContext,
  PurchaseResponse,
  EndpointMetrics
} from './services/session';
import './App.css';

function App() {
  const [session, setSession] = useState<SessionContext | null>(null);
  const [purchaseResponse, setPurchaseResponse] = useState<PurchaseResponse | null>(null);
  const [metrics, setMetrics] = useState<EndpointMetrics[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState<string[]>([]);
  const [purchaseData, setPurchaseData] = useState({
    schemeCode: 'AEF',
    amount: 5000
  });

  const log = useCallback((msg: string) => {
    setConsoleOutput(prev => [...prev, msg]);
    console.log(msg);
  }, []);

  const handleInitSession = async () => {
    setLoading(true);
    setError(null);
    setConsoleOutput([]);
    setMetrics([]);
    setPurchaseResponse(null);

    try {
      const result = await initSession(true, log);
      setSession(result.session);
      setMetrics([result.metrics]);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to initialize session';
      setError(message);
      console.error('Session init error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleMakePurchase = async () => {
    if (!session) return;

    setLoading(true);
    setError(null);
    setPurchaseResponse(null);

    try {
      const result = await makePurchase(session, purchaseData, true, log);
      setPurchaseResponse(result.response);
      setMetrics(prev => [...prev, result.metrics]);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to make purchase';
      setError(message);
      console.error('Purchase error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleClearSession = () => {
    setSession(null);
    setPurchaseResponse(null);
    setMetrics([]);
    setError(null);
    setConsoleOutput([]);
  };

  return (
    <div className="container">
      <header>
        <h1>Session Crypto PoC</h1>
        <p className="subtitle">React Single-SPA Client</p>
      </header>

      <main>
        {/* Session Status */}
        <section className="card">
          <h2>Session Status</h2>
          <div className={`status ${session ? 'active' : ''}`}>
            <span className="indicator"></span>
            <span>{session ? 'Active' : 'No Session'}</span>
          </div>
          {session && (
            <div className="session-info">
              <p><strong>Session ID:</strong> {session.sessionId}</p>
              <p><strong>Client ID:</strong> {session.clientId}</p>
              <p><strong>Key ID:</strong> {session.kid}</p>
            </div>
          )}
        </section>

        {/* Actions */}
        <section className="card">
          <h2>Actions</h2>
          <div className="actions">
            <button
              onClick={handleInitSession}
              disabled={loading}
              className="btn primary"
            >
              {loading ? 'Loading...' : 'Initialize Session'}
            </button>
            <button
              onClick={handleMakePurchase}
              disabled={loading || !session}
              className="btn secondary"
            >
              Make Purchase
            </button>
            <button
              onClick={handleClearSession}
              disabled={!session}
              className="btn danger"
            >
              Clear Session
            </button>
          </div>
        </section>

        {/* Purchase Form */}
        {session && (
          <section className="card">
            <h2>Purchase Details</h2>
            <div className="form-group">
              <label htmlFor="schemeCode">Scheme Code</label>
              <input
                id="schemeCode"
                type="text"
                value={purchaseData.schemeCode}
                onChange={(e) => setPurchaseData(prev => ({ ...prev, schemeCode: e.target.value }))}
                placeholder="e.g., AEF"
              />
            </div>
            <div className="form-group">
              <label htmlFor="amount">Amount</label>
              <input
                id="amount"
                type="number"
                value={purchaseData.amount}
                onChange={(e) => setPurchaseData(prev => ({ ...prev, amount: parseInt(e.target.value) || 0 }))}
                placeholder="e.g., 5000"
              />
            </div>
          </section>
        )}

        {/* Results */}
        {purchaseResponse && (
          <section className="card success">
            <h2>Purchase Response</h2>
            <pre>{JSON.stringify(purchaseResponse, null, 2)}</pre>
          </section>
        )}

        {/* Metrics */}
        {metrics.length > 0 && (
          <section className="card">
            <h2>Performance Metrics</h2>
            {metrics.map((m, idx) => (
              <div key={idx} className="metric-group">
                <h3>{m.endpoint}</h3>
                <div className="metric-row">
                  <span>Total Round-Trip:</span>
                  <span className="value">{m.totalMs.toFixed(2)} ms</span>
                </div>
                <div className="metric-row">
                  <span>HTTP Request:</span>
                  <span className="value">{m.httpMs.toFixed(2)} ms</span>
                </div>
                {m.cryptoOps.length > 0 && (
                  <div className="metric-section">
                    <h4>Client Crypto Operations:</h4>
                    {m.cryptoOps.map((op, i) => (
                      <div key={i} className="metric-row indent">
                        <span>{op.operation}:</span>
                        <span className="value">{op.durationMs.toFixed(3)} ms</span>
                      </div>
                    ))}
                  </div>
                )}
                {m.serverTiming.length > 0 && (
                  <div className="metric-section">
                    <h4>Server Timing:</h4>
                    {m.serverTiming.map((op, i) => (
                      <div key={i} className="metric-row indent">
                        <span>{op.operation}:</span>
                        <span className="value">{op.durationMs.toFixed(3)} ms</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </section>
        )}

        {/* Error */}
        {error && (
          <section className="card error">
            <h2>Error</h2>
            <p>{error}</p>
          </section>
        )}

        {/* Console Output */}
        {consoleOutput.length > 0 && (
          <section className="card console">
            <h2>Console Output</h2>
            <pre>{consoleOutput.join('\n')}</pre>
          </section>
        )}
      </main>

      <footer>
        <p>Client ID: {getClientId()} | Server: http://localhost:3000</p>
      </footer>
    </div>
  );
}

export default App;
