/**
 * API Client
 * Unified HTTP client for CLI-Backend communication
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import chalk from 'chalk';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';

export interface ApiConfig {
  baseURL: string;
  timeout?: number;
  headers?: Record<string, string>;
  auth?: {
    token?: string;
    username?: string;
    password?: string;
  };
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export class ApiClient {
  private client: AxiosInstance;
  private config: ApiConfig;

  constructor(config: ApiConfig) {
    this.config = {
      timeout: 30000,
      ...config,
    };

    this.client = axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
      },
    });

    // Add request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth header if token exists
        if (this.config.auth?.token) {
          config.headers.Authorization = `Bearer ${this.config.auth.token}`;
        }
        
        // Add dev bypass for localhost
        if (this.config.baseURL.includes('localhost')) {
          config.headers['x-dev-bypass'] = 'true';
        }

        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response) {
          // Server responded with error status
          const message = error.response.data?.message || error.response.data?.error || error.message;
          console.error(chalk.hex(KaliTheme.danger)(`${StatusIndicators.ERROR} API Error: ${message}`));
        } else if (error.request) {
          // Request made but no response
          console.error(chalk.hex(KaliTheme.danger)(`${StatusIndicators.ERROR} No response from server`));
        } else {
          // Error setting up request
          console.error(chalk.hex(KaliTheme.danger)(`${StatusIndicators.ERROR} Request error: ${error.message}`));
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * GET request
   */
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    try {
      const response = await this.client.get<T>(url, config);
      return this.handleResponse(response);
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * POST request
   */
  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    try {
      const response = await this.client.post<T>(url, data, config);
      return this.handleResponse(response);
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * PUT request
   */
  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    try {
      const response = await this.client.put<T>(url, data, config);
      return this.handleResponse(response);
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * DELETE request
   */
  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    try {
      const response = await this.client.delete<T>(url, config);
      return this.handleResponse(response);
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * Handle successful response
   */
  private handleResponse<T>(response: AxiosResponse<T>): ApiResponse<T> {
    return {
      success: true,
      data: response.data,
    };
  }

  /**
   * Handle error response
   */
  private handleError(error: any): ApiResponse {
    if (error.response) {
      return {
        success: false,
        error: error.response.data?.message || error.response.data?.error || 'API error',
        message: error.response.statusText,
      };
    } else if (error.request) {
      return {
        success: false,
        error: 'No response from server',
        message: 'Check if the backend is running',
      };
    } else {
      return {
        success: false,
        error: error.message || 'Unknown error',
      };
    }
  }

  /**
   * Set authentication token
   */
  setAuthToken(token: string): void {
    if (!this.config.auth) {
      this.config.auth = {};
    }
    this.config.auth.token = token;
  }

  /**
   * Clear authentication
   */
  clearAuth(): void {
    if (this.config.auth) {
      delete this.config.auth.token;
    }
  }

  /**
   * Update base URL
   */
  setBaseURL(url: string): void {
    this.config.baseURL = url;
    this.client.defaults.baseURL = url;
  }

  /**
   * Check if backend is reachable
   */
  async checkHealth(): Promise<boolean> {
    try {
      const response = await this.get('/health');
      return response.success;
    } catch {
      return false;
    }
  }

  // === Agent Mode Endpoints ===

  /**
   * Check agent service health
   */
  async checkAgentHealth(): Promise<ApiResponse> {
    return this.get('/api/agent/health');
  }

  /**
   * Recommend tools for a target
   */
  async recommendTools(target: string, operationType: string, agentMode = true): Promise<ApiResponse> {
    return this.post('/api/agent/recommend-tools', {
      target,
      operationType,
      agentMode,
    });
  }

  /**
   * Execute tool via agent framework
   */
  async executeTool(toolName: string, parameters: any, agentMode = true): Promise<ApiResponse> {
    return this.post('/api/agent/execute', {
      toolName,
      parameters,
      agentMode,
    });
  }

  // === Pentest Endpoints ===

  /**
   * Run basic pentest
   */
  async runPentest(target: string, options?: any): Promise<ApiResponse> {
    return this.post('/api/pentest/scan', {
      target,
      ...options,
    });
  }

  /**
   * Get pentest results
   */
  async getPentestResults(scanId: string): Promise<ApiResponse> {
    return this.get(`/api/pentest/results/${scanId}`);
  }

  // === Threat Intelligence Endpoints ===

  /**
   * Scan URL/IP/Hash with threat intelligence
   */
  async scanThreat(type: string, value: string): Promise<ApiResponse> {
    return this.post('/api/threat/scan', {
      type,
      value,
    });
  }

  // === Chat/AI Endpoints ===

  /**
   * Send chat message
   */
  async sendChatMessage(message: string, model?: string, context?: any): Promise<ApiResponse> {
    return this.post('/api/chat', {
      message,
      model,
      context,
    });
  }

  /**
   * Get AI analysis of scan results
   */
  async getAIAnalysis(results: any, context?: string): Promise<ApiResponse> {
    return this.post('/api/chat/analyze', {
      results,
      context,
    });
  }

  // === Bruteforce Endpoints ===

  /**
   * Start bruteforce attack
   */
  async startBruteforce(protocol: string, target: string, options?: any): Promise<ApiResponse> {
    return this.post('/api/bruteforce/start', {
      protocol,
      target,
      ...options,
    });
  }

  // === Attack Endpoints ===

  /**
   * Get attack options
   */
  async getAttackOptions(target: string): Promise<ApiResponse> {
    return this.post('/api/attack/options', { target });
  }

  /**
   * Execute attack vector
   */
  async executeAttack(attackType: string, target: string, options?: any): Promise<ApiResponse> {
    return this.post('/api/attack/execute', {
      attackType,
      target,
      ...options,
    });
  }

  // === Red Team Endpoints ===

  /**
   * Get available red team tools
   */
  async getRedTeamTools(): Promise<ApiResponse> {
    return this.get('/api/redteam/tools');
  }

  /**
   * Execute red team operation
   */
  async executeRedTeamOp(operation: string, params: any): Promise<ApiResponse> {
    return this.post('/api/redteam/execute', {
      operation,
      params,
    });
  }
}

// === Singleton Instance ===

let apiClientInstance: ApiClient | null = null;

export function getApiClient(baseURL?: string): ApiClient {
  if (!apiClientInstance || (baseURL && apiClientInstance['config'].baseURL !== baseURL)) {
    const url = baseURL || process.env.ZYPHERON_API_URL || 'http://localhost:3001';
    apiClientInstance = new ApiClient({ baseURL: url });
  }
  return apiClientInstance;
}

export function resetApiClient(): void {
  apiClientInstance = null;
}

