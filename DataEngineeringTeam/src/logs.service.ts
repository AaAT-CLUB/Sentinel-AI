import { Injectable } from '@nestjs/common';

export interface LogEntry {
  timestamp: string;
  method: string;
  url: string;
  statusCode: number;
  durationMs: number;
  ip: string;
  apiKeyPrefix: string;
}

@Injectable()
export class LogsService {
  private readonly entries: LogEntry[] = [];
  private readonly maxEntries = 1000;

  push(entry: LogEntry) {
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }
  }

  getAll(): LogEntry[] {
    return [...this.entries];
  }
}
