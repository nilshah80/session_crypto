import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { provideHttpClient } from '@angular/common/http';
import {
  SessionService,
  SessionContext,
  PurchaseResponse,
  EndpointMetrics
} from './services/session.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <header>
        <h1>Session Crypto PoC</h1>
        <p class="subtitle">Angular Single-SPA Client</p>
      </header>

      <main>
        <!-- Session Status -->
        <section class="card">
          <h2>Session Status</h2>
          <div class="status" [class.active]="session">
            <span class="indicator"></span>
            <span>{{ session ? 'Active' : 'No Session' }}</span>
          </div>
          @if (session) {
            <div class="session-info">
              <p><strong>Session ID:</strong> {{ session.sessionId }}</p>
              <p><strong>Client ID:</strong> {{ session.clientId }}</p>
              <p><strong>Key ID:</strong> {{ session.kid }}</p>
            </div>
          }
        </section>

        <!-- Actions -->
        <section class="card">
          <h2>Actions</h2>
          <div class="actions">
            <button
              (click)="initSession()"
              [disabled]="loading"
              class="btn primary"
            >
              {{ loading ? 'Loading...' : 'Initialize Session' }}
            </button>
            <button
              (click)="makePurchase()"
              [disabled]="loading || !session"
              class="btn secondary"
            >
              Make Purchase
            </button>
            <button
              (click)="clearSession()"
              [disabled]="!session"
              class="btn danger"
            >
              Clear Session
            </button>
          </div>
        </section>

        <!-- Purchase Form -->
        @if (session) {
          <section class="card">
            <h2>Purchase Details</h2>
            <div class="form-group">
              <label for="schemeCode">Scheme Code</label>
              <input
                id="schemeCode"
                type="text"
                [(ngModel)]="purchaseData.schemeCode"
                placeholder="e.g., AEF"
              />
            </div>
            <div class="form-group">
              <label for="amount">Amount</label>
              <input
                id="amount"
                type="number"
                [(ngModel)]="purchaseData.amount"
                placeholder="e.g., 5000"
              />
            </div>
          </section>
        }

        <!-- Results -->
        @if (purchaseResponse) {
          <section class="card success">
            <h2>Purchase Response</h2>
            <pre>{{ purchaseResponse | json }}</pre>
          </section>
        }

        <!-- Metrics -->
        @if (metrics.length > 0) {
          <section class="card">
            <h2>Performance Metrics</h2>
            @for (m of metrics; track m.endpoint) {
              <div class="metric-group">
                <h3>{{ m.endpoint }}</h3>
                <div class="metric-row">
                  <span>Total Round-Trip:</span>
                  <span class="value">{{ m.totalMs.toFixed(2) }} ms</span>
                </div>
                <div class="metric-row">
                  <span>HTTP Request:</span>
                  <span class="value">{{ m.httpMs.toFixed(2) }} ms</span>
                </div>
                @if (m.cryptoOps.length > 0) {
                  <div class="metric-section">
                    <h4>Client Crypto Operations:</h4>
                    @for (op of m.cryptoOps; track op.operation) {
                      <div class="metric-row indent">
                        <span>{{ op.operation }}:</span>
                        <span class="value">{{ op.durationMs.toFixed(3) }} ms</span>
                      </div>
                    }
                  </div>
                }
                @if (m.serverTiming.length > 0) {
                  <div class="metric-section">
                    <h4>Server Timing:</h4>
                    @for (op of m.serverTiming; track op.operation) {
                      <div class="metric-row indent">
                        <span>{{ op.operation }}:</span>
                        <span class="value">{{ op.durationMs.toFixed(3) }} ms</span>
                      </div>
                    }
                  </div>
                }
              </div>
            }
          </section>
        }

        <!-- Error -->
        @if (error) {
          <section class="card error">
            <h2>Error</h2>
            <p>{{ error }}</p>
          </section>
        }

        <!-- Console Output -->
        @if (consoleOutput.length > 0) {
          <section class="card console">
            <h2>Console Output</h2>
            <pre>{{ consoleOutput.join('\\n') }}</pre>
          </section>
        }
      </main>

      <footer>
        <p>Client ID: {{ sessionService.getClientId() }} | Server: http://localhost:3000</p>
      </footer>
    </div>
  `,
  styles: [`
    :host {
      display: block;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f0f0f;
      color: #e0e0e0;
      min-height: 100vh;
    }

    .container {
      max-width: 800px;
      margin: 0 auto;
      padding: 2rem;
    }

    header {
      text-align: center;
      margin-bottom: 2rem;
    }

    header h1 {
      font-size: 2rem;
      margin: 0;
      color: #fff;
    }

    .subtitle {
      color: #888;
      margin-top: 0.5rem;
    }

    .card {
      background: #1a1a1a;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
      border: 1px solid #333;
    }

    .card h2 {
      margin-top: 0;
      font-size: 1.25rem;
      color: #fff;
      border-bottom: 1px solid #333;
      padding-bottom: 0.5rem;
    }

    .card.success {
      border-color: #22c55e;
    }

    .card.error {
      border-color: #ef4444;
      color: #fca5a5;
    }

    .card.console {
      background: #0a0a0a;
    }

    .card.console pre {
      font-size: 0.75rem;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 300px;
      overflow-y: auto;
    }

    .status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 1.1rem;
    }

    .indicator {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: #ef4444;
    }

    .status.active .indicator {
      background: #22c55e;
    }

    .session-info {
      margin-top: 1rem;
      font-size: 0.9rem;
    }

    .session-info p {
      margin: 0.25rem 0;
      font-family: monospace;
    }

    .actions {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .btn {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-size: 1rem;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn.primary {
      background: #3b82f6;
      color: white;
    }

    .btn.primary:hover:not(:disabled) {
      background: #2563eb;
    }

    .btn.secondary {
      background: #6b7280;
      color: white;
    }

    .btn.secondary:hover:not(:disabled) {
      background: #4b5563;
    }

    .btn.danger {
      background: #ef4444;
      color: white;
    }

    .btn.danger:hover:not(:disabled) {
      background: #dc2626;
    }

    .form-group {
      margin-bottom: 1rem;
    }

    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      color: #888;
    }

    .form-group input {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid #333;
      border-radius: 6px;
      background: #0f0f0f;
      color: #e0e0e0;
      font-size: 1rem;
      box-sizing: border-box;
    }

    .form-group input:focus {
      outline: none;
      border-color: #3b82f6;
    }

    .metric-group {
      margin-bottom: 1.5rem;
    }

    .metric-group:last-child {
      margin-bottom: 0;
    }

    .metric-group h3 {
      font-size: 1rem;
      color: #3b82f6;
      margin: 0 0 0.5rem 0;
    }

    .metric-group h4 {
      font-size: 0.875rem;
      color: #888;
      margin: 0.75rem 0 0.25rem 0;
    }

    .metric-row {
      display: flex;
      justify-content: space-between;
      padding: 0.25rem 0;
      font-size: 0.9rem;
    }

    .metric-row.indent {
      padding-left: 1rem;
    }

    .metric-row .value {
      font-family: monospace;
      color: #22c55e;
    }

    pre {
      background: #0a0a0a;
      padding: 1rem;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.875rem;
      margin: 0;
    }

    footer {
      text-align: center;
      padding: 2rem 0;
      color: #666;
      font-size: 0.875rem;
    }
  `]
})
export class AppComponent {
  sessionService = inject(SessionService);

  session: SessionContext | null = null;
  purchaseResponse: PurchaseResponse | null = null;
  metrics: EndpointMetrics[] = [];
  error: string | null = null;
  loading = false;
  consoleOutput: string[] = [];

  purchaseData = {
    schemeCode: 'AEF',
    amount: 5000
  };

  // Override console.log to capture output
  private captureConsole() {
    const originalLog = console.log;
    console.log = (...args: any[]) => {
      this.consoleOutput.push(args.map(a =>
        typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)
      ).join(' '));
      originalLog.apply(console, args);
    };
  }

  private restoreConsole() {
    // Console will be restored on page refresh
  }

  async initSession() {
    this.loading = true;
    this.error = null;
    this.consoleOutput = [];
    this.metrics = [];
    this.purchaseResponse = null;

    this.captureConsole();

    try {
      const result = await this.sessionService.initSession(true);
      this.session = result.session;
      this.metrics.push(result.metrics);
    } catch (err: any) {
      this.error = err.message || 'Failed to initialize session';
      console.error('Session init error:', err);
    } finally {
      this.loading = false;
      this.restoreConsole();
    }
  }

  async makePurchase() {
    if (!this.session) return;

    this.loading = true;
    this.error = null;
    this.purchaseResponse = null;

    this.captureConsole();

    try {
      const result = await this.sessionService.makePurchase(this.purchaseData, true);
      this.purchaseResponse = result.response;
      this.metrics.push(result.metrics);
    } catch (err: any) {
      this.error = err.message || 'Failed to make purchase';
      console.error('Purchase error:', err);
    } finally {
      this.loading = false;
      this.restoreConsole();
    }
  }

  clearSession() {
    this.sessionService.clearSession();
    this.session = null;
    this.purchaseResponse = null;
    this.metrics = [];
    this.error = null;
    this.consoleOutput = [];
  }
}
