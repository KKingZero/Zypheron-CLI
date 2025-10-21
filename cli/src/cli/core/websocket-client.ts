/**
 * WebSocket Client
 * Real-time updates from backend
 */

import WebSocket from 'ws';
import chalk from 'chalk';
import { EventEmitter } from 'events';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';

export interface WebSocketConfig {
  url: string;
  reconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export interface WebSocketMessage {
  type: string;
  data?: any;
  timestamp?: string;
  message?: string;
}

export class WebSocketClient extends EventEmitter {
  private ws: WebSocket | null = null;
  private config: WebSocketConfig;
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isConnected = false;

  constructor(config: WebSocketConfig) {
    super();
    this.config = {
      reconnect: true,
      reconnectInterval: 3000,
      maxReconnectAttempts: 5,
      ...config,
    };
  }

  /**
   * Connect to WebSocket server
   */
  async connect(type: string = 'agent'): Promise<void> {
    return new Promise((resolve, reject) => {
      const wsUrl = this.config.url.replace('http', 'ws') + `/?type=${type}`;
      
      try {
        this.ws = new WebSocket(wsUrl);

        this.ws.on('open', () => {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          console.log(chalk.hex(KaliTheme.success)(`${StatusIndicators.SUCCESS} WebSocket connected`));
          this.emit('connected');
          resolve();
        });

        this.ws.on('message', (data: WebSocket.Data) => {
          try {
            const message: WebSocketMessage = JSON.parse(data.toString());
            this.handleMessage(message);
          } catch (error) {
            console.error(chalk.hex(KaliTheme.danger)('Failed to parse WebSocket message'));
          }
        });

        this.ws.on('error', (error) => {
          console.error(chalk.hex(KaliTheme.danger)(`${StatusIndicators.ERROR} WebSocket error: ${error.message}`));
          this.emit('error', error);
          reject(error);
        });

        this.ws.on('close', () => {
          this.isConnected = false;
          console.log(chalk.hex(KaliTheme.warning)(`${StatusIndicators.WARNING} WebSocket disconnected`));
          this.emit('disconnected');
          
          if (this.config.reconnect && this.reconnectAttempts < (this.config.maxReconnectAttempts || 5)) {
            this.attemptReconnect(type);
          }
        });

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Handle incoming WebSocket message
   */
  private handleMessage(message: WebSocketMessage): void {
    switch (message.type) {
      case 'connection':
        console.log(chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} ${message.message}`));
        break;

      case 'job-progress':
        this.emit('job-progress', message.data);
        this.displayJobProgress(message.data);
        break;

      case 'job-completed':
        this.emit('job-completed', message.data);
        console.log(chalk.hex(KaliTheme.success)(`${StatusIndicators.SUCCESS} Job ${message.data?.jobId} completed`));
        break;

      case 'scan-update':
        this.emit('scan-update', message.data);
        this.displayScanUpdate(message.data);
        break;

      case 'ai-analysis':
        this.emit('ai-analysis', message.data);
        this.displayAIAnalysis(message.data);
        break;

      case 'tool-output':
        this.emit('tool-output', message.data);
        console.log(chalk.hex(KaliTheme.foreground)(message.data?.output || ''));
        break;

      case 'error':
        this.emit('error-message', message);
        console.error(chalk.hex(KaliTheme.danger)(`${StatusIndicators.ERROR} ${message.message}`));
        break;

      default:
        this.emit('message', message);
    }
  }

  /**
   * Display job progress
   */
  private displayJobProgress(data: any): void {
    if (!data) return;

    const progress = data.progress || 0;
    const status = data.status || 'running';
    const tool = data.tool || 'unknown';

    const progressBar = this.createProgressBar(progress);
    console.log(
      chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} ${tool}: ${progressBar} ${progress}% - ${status}`)
    );
  }

  /**
   * Display scan update
   */
  private displayScanUpdate(data: any): void {
    if (!data) return;

    console.log(chalk.hex(KaliTheme.accent)(`\n${StatusIndicators.INFO} Scan Update:`));
    console.log(`  Phase: ${data.phase || 'unknown'}`);
    console.log(`  Target: ${data.target || 'unknown'}`);
    if (data.findings) {
      console.log(`  Findings: ${data.findings.length}`);
    }
  }

  /**
   * Display AI analysis
   */
  private displayAIAnalysis(data: any): void {
    if (!data) return;

    console.log();
    console.log(chalk.hex(KaliTheme.accent).bold('🤖 AI Analysis:'));
    console.log(chalk.hex(KaliTheme.foreground)('─'.repeat(60)));
    
    if (data.recommendations) {
      console.log(chalk.hex(KaliTheme.info).bold('\nRecommendations:'));
      data.recommendations.forEach((rec: string, index: number) => {
        console.log(`  ${index + 1}. ${rec}`);
      });
    }

    if (data.insights) {
      console.log(chalk.hex(KaliTheme.info).bold('\nInsights:'));
      console.log(`  ${data.insights}`);
    }
  }

  /**
   * Create ASCII progress bar
   */
  private createProgressBar(progress: number, width: number = 20): string {
    const filled = Math.round((progress / 100) * width);
    const empty = width - filled;
    return chalk.hex(KaliTheme.success)('█'.repeat(filled)) + 
           chalk.hex(KaliTheme.muted)('░'.repeat(empty));
  }

  /**
   * Attempt to reconnect
   */
  private attemptReconnect(type: string): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectAttempts++;
    console.log(
      chalk.hex(KaliTheme.warning)(
        `${StatusIndicators.WARNING} Reconnecting... (${this.reconnectAttempts}/${this.config.maxReconnectAttempts})`
      )
    );

    this.reconnectTimer = setTimeout(() => {
      this.connect(type).catch(() => {
        // Reconnect will be attempted again if configured
      });
    }, this.config.reconnectInterval);
  }

  /**
   * Send message to server
   */
  send(type: string, data?: any): void {
    if (!this.isConnected || !this.ws) {
      console.error(chalk.hex(KaliTheme.danger)('WebSocket not connected'));
      return;
    }

    const message: WebSocketMessage = {
      type,
      data,
      timestamp: new Date().toISOString(),
    };

    this.ws.send(JSON.stringify(message));
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.config.reconnect = false; // Prevent automatic reconnection

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this.isConnected = false;
  }

  /**
   * Check if connected
   */
  connected(): boolean {
    return this.isConnected;
  }
}

// Singleton instance
let wsClientInstance: WebSocketClient | null = null;

export function getWebSocketClient(url?: string): WebSocketClient {
  if (!wsClientInstance || (url && wsClientInstance['config'].url !== url)) {
    const wsUrl = url || process.env.ZYPHERON_API_URL || 'http://localhost:3001';
    wsClientInstance = new WebSocketClient({ url: wsUrl });
  }
  return wsClientInstance;
}

export function disconnectWebSocket(): void {
  if (wsClientInstance) {
    wsClientInstance.disconnect();
    wsClientInstance = null;
  }
}

