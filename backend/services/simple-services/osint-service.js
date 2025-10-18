#!/usr/bin/env node

/**
 * COBRA AI OSINT Service - Node.js Implementation
 * Simplified version for development mode
 */

const express = require('express');
const cors = require('cors');
const dns = require('dns');
const http = require('http');
const https = require('https');
const { promisify } = require('util');

const app = express();
const PORT = process.env.OSINT_SERVICE_PORT || 8001;

// Middleware
app.use(cors());
app.use(express.json());

// Promisify DNS functions
const lookup = promisify(dns.lookup);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'COBRA AI OSINT Service',
    version: '1.0.0-dev',
    timestamp: new Date().toISOString()
  });
});

// OSINT data gathering endpoint
app.post('/api/osint/gather', async (req, res) => {
  try {
    const { target, tools = {}, options = {} } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    console.log(`🔍 [OSINT] Starting reconnaissance for: ${target}`);

    const results = {
      target,
      timestamp: new Date().toISOString(),
      sources_checked: [],
      data_found: {}
    };

    // DNS Information
    if (tools.dns !== false) {
      results.sources_checked.push('DNS');
      try {
        const dnsInfo = await gatherDnsInfo(target);
        results.data_found.dns = dnsInfo;
        console.log(`✅ [OSINT] DNS lookup completed for ${target}`);
      } catch (error) {
        console.log(`❌ [OSINT] DNS lookup failed for ${target}: ${error.message}`);
        results.data_found.dns = { error: error.message };
      }
    }

    // HTTP Headers
    if (tools.http !== false) {
      results.sources_checked.push('HTTP');
      try {
        const httpInfo = await gatherHttpInfo(target);
        results.data_found.http = httpInfo;
        console.log(`✅ [OSINT] HTTP analysis completed for ${target}`);
      } catch (error) {
        console.log(`❌ [OSINT] HTTP analysis failed for ${target}: ${error.message}`);
        results.data_found.http = { error: error.message };
      }
    }

    // Port Information (basic)
    if (tools.ports !== false) {
      results.sources_checked.push('Ports');
      try {
        const portInfo = await gatherPortInfo(target);
        results.data_found.ports = portInfo;
        console.log(`✅ [OSINT] Port scan completed for ${target}`);
      } catch (error) {
        console.log(`❌ [OSINT] Port scan failed for ${target}: ${error.message}`);
        results.data_found.ports = { error: error.message };
      }
    }

    // Threat Intelligence (mock data for demo)
    if (tools.threat_intel !== false) {
      results.sources_checked.push('Threat Intelligence');
      results.data_found.threat_intel = {
        reputation: 'Clean',
        malware_families: [],
        threat_actors: [],
        iocs: [],
        risk_score: Math.floor(Math.random() * 100),
        last_seen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString()
      };
      console.log(`✅ [OSINT] Threat intelligence check completed for ${target}`);
    }

    res.json(results);

  } catch (error) {
    console.error(`❌ [OSINT] Error processing request:`, error);
    res.status(500).json({ 
      error: 'Internal server error', 
      message: error.message 
    });
  }
});

// DNS Information gathering
async function gatherDnsInfo(domain) {
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  
  const dnsInfo = {
    domain: cleanDomain,
    records: {}
  };

  try {
    // A record
    const aRecord = await lookup(cleanDomain, 4);
    dnsInfo.records.A = [aRecord.address];
  } catch (error) {
    dnsInfo.records.A = [];
  }

  try {
    // MX records
    const mxRecords = await resolveMx(cleanDomain);
    dnsInfo.records.MX = mxRecords.map(mx => ({
      exchange: mx.exchange,
      priority: mx.priority
    }));
  } catch (error) {
    dnsInfo.records.MX = [];
  }

  try {
    // TXT records
    const txtRecords = await resolveTxt(cleanDomain);
    dnsInfo.records.TXT = txtRecords.flat();
  } catch (error) {
    dnsInfo.records.TXT = [];
  }

  return dnsInfo;
}

// HTTP Information gathering
async function gatherHttpInfo(target) {
  return new Promise((resolve, reject) => {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const isHttps = url.startsWith('https');
    const client = isHttps ? https : http;

    const req = client.request(url, { 
      method: 'HEAD',
      timeout: 5000,
      headers: {
        'User-Agent': 'COBRA-AI-OSINT/1.0'
      }
    }, (res) => {
      const httpInfo = {
        status_code: res.statusCode,
        headers: res.headers,
        ssl: isHttps,
        server: res.headers.server || 'Unknown',
        technologies: []
      };

      // Detect technologies from headers
      if (res.headers['x-powered-by']) {
        httpInfo.technologies.push(res.headers['x-powered-by']);
      }
      if (res.headers.server) {
        httpInfo.technologies.push(res.headers.server);
      }

      resolve(httpInfo);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.end();
  });
}

// Port Information gathering (basic TCP check)
async function gatherPortInfo(target) {
  const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
  
  const portInfo = {
    target: cleanTarget,
    open_ports: [],
    closed_ports: [],
    scan_time: new Date().toISOString()
  };

  const portPromises = commonPorts.map(port => checkPort(cleanTarget, port));
  const results = await Promise.allSettled(portPromises);

  results.forEach((result, index) => {
    const port = commonPorts[index];
    if (result.status === 'fulfilled' && result.value) {
      portInfo.open_ports.push({
        port,
        service: getServiceName(port),
        state: 'open'
      });
    } else {
      portInfo.closed_ports.push(port);
    }
  });

  return portInfo;
}

// Check if a specific port is open
function checkPort(host, port) {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();
    
    socket.setTimeout(1000);
    
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', () => {
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

// Get service name for common ports
function getServiceName(port) {
  const services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
  };
  return services[port] || 'Unknown';
}

// Shodan-like endpoint (mock)
app.post('/api/osint/shodan', async (req, res) => {
  const { query, facets } = req.body;
  
  // Return mock Shodan-like data
  res.json({
    query,
    total: Math.floor(Math.random() * 1000),
    results: [
      {
        ip: '192.168.1.1',
        port: 80,
        banner: 'HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0',
        location: { country: 'US', city: 'New York' },
        org: 'Example Organization',
        last_update: new Date().toISOString()
      }
    ]
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`🐍 [OSINT] Service started on port ${PORT}`);
  console.log(`🔍 [OSINT] Ready to perform reconnaissance operations`);
  console.log(`📡 [OSINT] Health check: http://localhost:${PORT}/health`);
});