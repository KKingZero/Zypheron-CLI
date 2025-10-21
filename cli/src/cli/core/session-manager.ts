/**
 * Session Manager
 * Persist CLI sessions, scan history, and configuration
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { promisify } from 'util';

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);
const existsAsync = promisify(fs.exists);

export interface ScanSession {
  id: string;
  tool: string;
  target: string;
  timestamp: number;
  duration?: number;
  success: boolean;
  result?: any;
  aiInsights?: string;
}

export interface ChatHistory {
  id: string;
  timestamp: number;
  messages: Array<{
    role: 'user' | 'assistant';
    content: string;
    timestamp: number;
  }>;
}

export interface SessionData {
  version: string;
  lastUpdated: number;
  config: {
    apiUrl?: string;
    defaultModel?: string;
    preferences?: Record<string, any>;
  };
  scanHistory: ScanSession[];
  chatHistory: ChatHistory[];
  activeSession?: {
    chatId?: string;
    lastCommand?: string;
  };
}

export class SessionManager {
  private dataDir: string;
  private sessionFile: string;
  private data: SessionData;
  private maxHistoryEntries = 100;

  constructor() {
    // Use XDG Base Directory specification or fallback to home directory
    const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    this.dataDir = path.join(configHome, 'zypheron-cli');
    this.sessionFile = path.join(this.dataDir, 'session.json');
    
    this.data = this.getDefaultData();
  }

  /**
   * Initialize session manager (create directories, load data)
   */
  async initialize(): Promise<void> {
    try {
      // Ensure directory exists
      if (!fs.existsSync(this.dataDir)) {
        await mkdirAsync(this.dataDir, { recursive: true });
      }

      // Load existing session data
      if (fs.existsSync(this.sessionFile)) {
        await this.load();
      } else {
        // Create new session file
        await this.save();
      }
    } catch (error: any) {
      console.warn(`Failed to initialize session manager: ${error.message}`);
    }
  }

  /**
   * Get default session data
   */
  private getDefaultData(): SessionData {
    return {
      version: '1.0.0',
      lastUpdated: Date.now(),
      config: {},
      scanHistory: [],
      chatHistory: [],
      activeSession: {},
    };
  }

  /**
   * Load session data from file
   */
  async load(): Promise<void> {
    try {
      const content = await readFileAsync(this.sessionFile, 'utf-8');
      this.data = JSON.parse(content);
      
      // Migrate old data if needed
      if (!this.data.version) {
        this.data.version = '1.0.0';
      }
    } catch (error: any) {
      console.warn(`Failed to load session data: ${error.message}`);
      this.data = this.getDefaultData();
    }
  }

  /**
   * Save session data to file
   */
  async save(): Promise<void> {
    try {
      this.data.lastUpdated = Date.now();
      const content = JSON.stringify(this.data, null, 2);
      await writeFileAsync(this.sessionFile, content, 'utf-8');
    } catch (error: any) {
      console.warn(`Failed to save session data: ${error.message}`);
    }
  }

  /**
   * Add scan to history
   */
  async addScan(scan: ScanSession): Promise<void> {
    this.data.scanHistory.unshift(scan);
    
    // Keep only last N entries
    if (this.data.scanHistory.length > this.maxHistoryEntries) {
      this.data.scanHistory = this.data.scanHistory.slice(0, this.maxHistoryEntries);
    }
    
    await this.save();
  }

  /**
   * Get scan history
   */
  getScanHistory(limit?: number, tool?: string): ScanSession[] {
    let history = this.data.scanHistory;
    
    if (tool) {
      history = history.filter(scan => scan.tool === tool);
    }
    
    if (limit) {
      history = history.slice(0, limit);
    }
    
    return history;
  }

  /**
   * Get specific scan by ID
   */
  getScan(id: string): ScanSession | undefined {
    return this.data.scanHistory.find(scan => scan.id === id);
  }

  /**
   * Clear scan history
   */
  async clearScanHistory(): Promise<void> {
    this.data.scanHistory = [];
    await this.save();
  }

  /**
   * Add chat history
   */
  async addChatHistory(history: ChatHistory): Promise<void> {
    this.data.chatHistory.unshift(history);
    
    // Keep only last N entries
    if (this.data.chatHistory.length > this.maxHistoryEntries) {
      this.data.chatHistory = this.data.chatHistory.slice(0, this.maxHistoryEntries);
    }
    
    await this.save();
  }

  /**
   * Get chat history
   */
  getChatHistory(limit?: number): ChatHistory[] {
    if (limit) {
      return this.data.chatHistory.slice(0, limit);
    }
    return this.data.chatHistory;
  }

  /**
   * Get specific chat by ID
   */
  getChat(id: string): ChatHistory | undefined {
    return this.data.chatHistory.find(chat => chat.id === id);
  }

  /**
   * Set active chat session
   */
  async setActiveChat(chatId: string): Promise<void> {
    if (!this.data.activeSession) {
      this.data.activeSession = {};
    }
    this.data.activeSession.chatId = chatId;
    await this.save();
  }

  /**
   * Get active chat session
   */
  getActiveChat(): string | undefined {
    return this.data.activeSession?.chatId;
  }

  /**
   * Set last command
   */
  async setLastCommand(command: string): Promise<void> {
    if (!this.data.activeSession) {
      this.data.activeSession = {};
    }
    this.data.activeSession.lastCommand = command;
    await this.save();
  }

  /**
   * Get last command
   */
  getLastCommand(): string | undefined {
    return this.data.activeSession?.lastCommand;
  }

  /**
   * Set configuration value
   */
  async setConfig(key: string, value: any): Promise<void> {
    if (!this.data.config) {
      this.data.config = {};
    }
    
    // Support nested keys like "ai.defaultModel"
    const keys = key.split('.');
    let current: any = this.data.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
    await this.save();
  }

  /**
   * Get configuration value
   */
  getConfig(key?: string): any {
    if (!key) {
      return this.data.config;
    }
    
    // Support nested keys like "ai.defaultModel"
    const keys = key.split('.');
    let current: any = this.data.config;
    
    for (const k of keys) {
      if (current && typeof current === 'object' && k in current) {
        current = current[k];
      } else {
        return undefined;
      }
    }
    
    return current;
  }

  /**
   * Delete configuration value
   */
  async deleteConfig(key: string): Promise<void> {
    if (!this.data.config) {
      return;
    }
    
    const keys = key.split('.');
    let current: any = this.data.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        return;
      }
      current = current[keys[i]];
    }
    
    delete current[keys[keys.length - 1]];
    await this.save();
  }

  /**
   * Get session file path
   */
  getSessionPath(): string {
    return this.sessionFile;
  }

  /**
   * Export session data
   */
  exportData(): SessionData {
    return JSON.parse(JSON.stringify(this.data));
  }

  /**
   * Import session data
   */
  async importData(data: Partial<SessionData>): Promise<void> {
    this.data = {
      ...this.getDefaultData(),
      ...data,
      version: '1.0.0',
      lastUpdated: Date.now(),
    };
    await this.save();
  }

  /**
   * Clear all session data
   */
  async clear(): Promise<void> {
    this.data = this.getDefaultData();
    await this.save();
  }
}

// Singleton instance
let sessionManagerInstance: SessionManager | null = null;

export async function getSessionManager(): Promise<SessionManager> {
  if (!sessionManagerInstance) {
    sessionManagerInstance = new SessionManager();
    await sessionManagerInstance.initialize();
  }
  return sessionManagerInstance;
}

