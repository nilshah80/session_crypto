import { performance } from "perf_hooks";

export interface OperationTiming {
  operation: string;
  durationMs: number;
}

export interface RequestMetrics {
  endpoint: string;
  totalMs: number;
  operations: OperationTiming[];
}

export class MetricsCollector {
  private startTime: number;
  private operations: OperationTiming[] = [];
  private endpoint: string;

  constructor(endpoint: string) {
    this.endpoint = endpoint;
    this.startTime = performance.now();
  }

  // Measure a synchronous operation
  measure<T>(operation: string, fn: () => T): T {
    const start = performance.now();
    const result = fn();
    this.operations.push({
      operation,
      durationMs: performance.now() - start,
    });
    return result;
  }

  // Measure an async operation
  async measureAsync<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    const result = await fn();
    this.operations.push({
      operation,
      durationMs: performance.now() - start,
    });
    return result;
  }

  // Get final metrics
  finalize(): RequestMetrics {
    return {
      endpoint: this.endpoint,
      totalMs: performance.now() - this.startTime,
      operations: this.operations,
    };
  }

  // Format as W3C Server-Timing header
  toServerTimingHeader(): string {
    const parts = this.operations.map(
      (op) =>
        `${op.operation.replace(/\s+/g, "-")};dur=${op.durationMs.toFixed(3)}`
    );
    parts.push(`total;dur=${(performance.now() - this.startTime).toFixed(3)}`);
    return parts.join(", ");
  }
}
