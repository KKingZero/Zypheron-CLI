#!/usr/bin/env node

/**
 * COBRA AI Packet Manipulator Service - Node.js Implementation
 * Network packet capture and manipulation service
 */

const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PACKET_SERVICE_PORT || 8003;

// Middleware
app.use(cors());
app.use(express.json());

// Store active captures
const activeCaptures = new Map();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'COBRA AI Packet Manipulator',
    version: '1.0.0-dev',
    capabilities: ['packet_capture', 'packet_analysis', 'traffic_generation', 'protocol_analysis'],
    active_captures: activeCaptures.size,
    timestamp: new Date().toISOString()
  });
});

// Start packet capture endpoint
app.post('/api/packet/capture/start', async (req, res) => {
  try {
    const {
      interface: iface = 'any',
      filter = '',
      duration = 60,
      max_packets = 1000,
      output_format = 'json'
    } = req.body;

    const captureId = generateCaptureId();
    
    console.log(`📦 [PACKET] Starting packet capture ${captureId} on interface: ${iface}`);

    const captureSession = await startPacketCapture({
      captureId,
      interface: iface,
      filter,
      duration,
      max_packets,
      output_format
    });

    activeCaptures.set(captureId, captureSession);

    res.json({
      capture_id: captureId,
      status: 'started',
      interface: iface,
      filter,
      duration,
      max_packets,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error starting capture:`, error);
    res.status(500).json({ 
      error: 'Capture start error', 
      message: error.message 
    });
  }
});

// Stop packet capture endpoint
app.post('/api/packet/capture/stop', async (req, res) => {
  try {
    const { capture_id } = req.body;

    if (!capture_id || !activeCaptures.has(capture_id)) {
      return res.status(404).json({ error: 'Capture not found' });
    }

    console.log(`📦 [PACKET] Stopping packet capture ${capture_id}`);

    const results = await stopPacketCapture(capture_id);
    activeCaptures.delete(capture_id);

    res.json({
      capture_id,
      status: 'stopped',
      packets_captured: results.packets_captured,
      file_path: results.file_path,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error stopping capture:`, error);
    res.status(500).json({ 
      error: 'Capture stop error', 
      message: error.message 
    });
  }
});

// Get capture status endpoint
app.get('/api/packet/capture/:captureId/status', (req, res) => {
  const { captureId } = req.params;
  
  if (!activeCaptures.has(captureId)) {
    return res.status(404).json({ error: 'Capture not found' });
  }

  const capture = activeCaptures.get(captureId);
  
  res.json({
    capture_id: captureId,
    status: capture.status,
    packets_captured: capture.packets_captured,
    start_time: capture.start_time,
    elapsed_time: Date.now() - capture.start_time,
    interface: capture.interface
  });
});

// Analyze packets endpoint
app.post('/api/packet/analyze', async (req, res) => {
  try {
    const { capture_file, analysis_type = 'summary' } = req.body;

    if (!capture_file) {
      return res.status(400).json({ error: 'Capture file path is required' });
    }

    console.log(`🔍 [PACKET] Analyzing packets from: ${capture_file}`);

    const analysis = await analyzePackets(capture_file, analysis_type);

    res.json({
      file: capture_file,
      analysis_type,
      timestamp: new Date().toISOString(),
      results: analysis
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error analyzing packets:`, error);
    res.status(500).json({ 
      error: 'Packet analysis error', 
      message: error.message 
    });
  }
});

// Generate traffic endpoint
app.post('/api/packet/generate', async (req, res) => {
  try {
    const {
      target_ip,
      target_port,
      protocol = 'tcp',
      packet_count = 10,
      interval_ms = 1000,
      payload = ''
    } = req.body;

    if (!target_ip || !target_port) {
      return res.status(400).json({ error: 'Target IP and port are required' });
    }

    console.log(`🚀 [PACKET] Generating ${protocol.toUpperCase()} traffic to ${target_ip}:${target_port}`);

    const results = await generateTraffic({
      target_ip,
      target_port,
      protocol,
      packet_count,
      interval_ms,
      payload
    });

    res.json({
      target: `${target_ip}:${target_port}`,
      protocol,
      packets_sent: results.packets_sent,
      responses_received: results.responses_received,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error generating traffic:`, error);
    res.status(500).json({ 
      error: 'Traffic generation error', 
      message: error.message 
    });
  }
});

// Protocol analysis endpoint
app.post('/api/packet/protocol/analyze', async (req, res) => {
  try {
    const { packets, protocol_type } = req.body;

    if (!packets || !Array.isArray(packets)) {
      return res.status(400).json({ error: 'Packets array is required' });
    }

    console.log(`🔍 [PACKET] Analyzing ${protocol_type} protocol packets`);

    const analysis = await analyzeProtocol(packets, protocol_type);

    res.json({
      protocol: protocol_type,
      packets_analyzed: packets.length,
      analysis,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error analyzing protocol:`, error);
    res.status(500).json({ 
      error: 'Protocol analysis error', 
      message: error.message 
    });
  }
});

// List network interfaces endpoint
app.get('/api/packet/interfaces', async (req, res) => {
  try {
    const interfaces = await getNetworkInterfaces();
    
    res.json({
      interfaces,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error listing interfaces:`, error);
    res.status(500).json({ 
      error: 'Interface listing error', 
      message: error.message 
    });
  }
});

// Implementation functions

async function startPacketCapture(options) {
  const captureSession = {
    captureId: options.captureId,
    interface: options.interface,
    filter: options.filter,
    status: 'running',
    packets_captured: 0,
    start_time: Date.now(),
    file_path: path.join(__dirname, 'captures', `${options.captureId}.pcap`)
  };

  // Create captures directory if it doesn't exist
  const capturesDir = path.join(__dirname, 'captures');
  if (!fs.existsSync(capturesDir)) {
    fs.mkdirSync(capturesDir, { recursive: true });
  }

  // Mock packet capture (in real implementation, would use tcpdump/tshark)
  captureSession.mockCapture = setInterval(() => {
    captureSession.packets_captured += Math.floor(Math.random() * 10) + 1;
    
    // Auto-stop after duration
    if (Date.now() - captureSession.start_time > options.duration * 1000) {
      clearInterval(captureSession.mockCapture);
      captureSession.status = 'completed';
    }
    
    // Auto-stop if max packets reached
    if (captureSession.packets_captured >= options.max_packets) {
      clearInterval(captureSession.mockCapture);
      captureSession.status = 'completed';
    }
  }, 1000);

  return captureSession;
}

async function stopPacketCapture(captureId) {
  const capture = activeCaptures.get(captureId);
  
  if (capture.mockCapture) {
    clearInterval(capture.mockCapture);
  }
  
  capture.status = 'stopped';
  
  // Generate mock capture file
  const mockPcapData = generateMockPcapData(capture.packets_captured);
  fs.writeFileSync(capture.file_path, mockPcapData);
  
  return {
    packets_captured: capture.packets_captured,
    file_path: capture.file_path
  };
}

async function analyzePackets(captureFile, analysisType) {
  // Mock packet analysis
  const mockPackets = [
    { protocol: 'TCP', src: '192.168.1.100', dst: '192.168.1.1', port: 80, size: 1514 },
    { protocol: 'UDP', src: '192.168.1.100', dst: '8.8.8.8', port: 53, size: 74 },
    { protocol: 'HTTP', src: '192.168.1.100', dst: '192.168.1.1', port: 80, size: 2048 },
    { protocol: 'HTTPS', src: '192.168.1.100', dst: '172.217.14.142', port: 443, size: 1200 }
  ];

  const analysis = {
    total_packets: mockPackets.length,
    protocols: {},
    top_talkers: {},
    traffic_flow: {
      inbound: Math.floor(Math.random() * 1000),
      outbound: Math.floor(Math.random() * 1000)
    },
    suspicious_activity: []
  };

  // Protocol distribution
  mockPackets.forEach(packet => {
    analysis.protocols[packet.protocol] = (analysis.protocols[packet.protocol] || 0) + 1;
  });

  // Top talkers
  mockPackets.forEach(packet => {
    const key = `${packet.src} -> ${packet.dst}`;
    analysis.top_talkers[key] = (analysis.top_talkers[key] || 0) + packet.size;
  });

  // Mock suspicious activity detection
  if (Math.random() > 0.7) {
    analysis.suspicious_activity.push({
      type: 'Port Scan',
      source: '192.168.1.200',
      description: 'Multiple connection attempts to different ports',
      severity: 'Medium',
      timestamp: new Date().toISOString()
    });
  }

  if (Math.random() > 0.8) {
    analysis.suspicious_activity.push({
      type: 'DDoS Pattern',
      source: 'Multiple',
      description: 'High volume traffic from multiple sources',
      severity: 'High',
      timestamp: new Date().toISOString()
    });
  }

  return analysis;
}

async function generateTraffic(options) {
  console.log(`Generating ${options.packet_count} ${options.protocol} packets to ${options.target_ip}:${options.target_port}`);
  
  // Mock traffic generation
  const results = {
    packets_sent: 0,
    responses_received: 0,
    errors: []
  };

  for (let i = 0; i < options.packet_count; i++) {
    await new Promise(resolve => setTimeout(resolve, options.interval_ms));
    
    results.packets_sent++;
    
    // Mock response rate
    if (Math.random() > 0.2) {
      results.responses_received++;
    }
  }

  return results;
}

async function analyzeProtocol(packets, protocolType) {
  const analysis = {
    protocol: protocolType,
    statistics: {
      total_packets: packets.length,
      average_size: packets.reduce((sum, p) => sum + (p.size || 0), 0) / packets.length,
      unique_sources: new Set(packets.map(p => p.src)).size,
      unique_destinations: new Set(packets.map(p => p.dst)).size
    },
    patterns: [],
    anomalies: []
  };

  // Protocol-specific analysis
  switch (protocolType.toUpperCase()) {
    case 'HTTP':
      analysis.patterns.push('Standard HTTP GET/POST requests');
      analysis.http_methods = { GET: 0, POST: 0, PUT: 0, DELETE: 0 };
      // Mock HTTP method distribution
      packets.forEach(() => {
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const method = methods[Math.floor(Math.random() * methods.length)];
        analysis.http_methods[method]++;
      });
      break;
      
    case 'TCP':
      analysis.patterns.push('TCP three-way handshake observed');
      analysis.tcp_flags = { SYN: 0, ACK: 0, FIN: 0, RST: 0 };
      break;
      
    case 'DNS':
      analysis.patterns.push('DNS query/response pairs');
      analysis.query_types = { A: 0, AAAA: 0, MX: 0, TXT: 0 };
      break;
  }

  // Mock anomaly detection
  if (Math.random() > 0.6) {
    analysis.anomalies.push({
      type: 'Unusual packet size',
      description: 'Packet size significantly larger than normal',
      packets_affected: Math.floor(Math.random() * 5) + 1
    });
  }

  return analysis;
}

async function getNetworkInterfaces() {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  
  const result = [];
  
  Object.keys(interfaces).forEach(name => {
    const iface = interfaces[name];
    const external = iface.find(alias => alias.family === 'IPv4' && !alias.internal);
    
    if (external) {
      result.push({
        name,
        address: external.address,
        family: external.family,
        internal: external.internal,
        mac: external.mac
      });
    }
  });

  // Add common interface names
  result.push(
    { name: 'any', address: '0.0.0.0', family: 'IPv4', internal: false, mac: '00:00:00:00:00:00' },
    { name: 'eth0', address: '192.168.1.100', family: 'IPv4', internal: false, mac: '02:42:ac:11:00:02' },
    { name: 'wlan0', address: '192.168.1.101', family: 'IPv4', internal: false, mac: '02:42:ac:11:00:03' }
  );

  return result;
}

// Utility functions
function generateCaptureId() {
  return 'capture_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function generateMockPcapData(packetCount) {
  // Generate a mock binary data for demonstration
  // In real implementation, this would be actual PCAP format
  const header = Buffer.from('MOCK_PCAP_HEADER');
  const packetData = Buffer.from(`MOCK_PACKET_DATA_${packetCount}_PACKETS`);
  return Buffer.concat([header, packetData]);
}

// Packet manipulation endpoints

// Create custom packet endpoint
app.post('/api/packet/create', async (req, res) => {
  try {
    const {
      protocol = 'tcp',
      src_ip,
      dst_ip,
      src_port,
      dst_port,
      payload = '',
      flags = []
    } = req.body;

    console.log(`🔧 [PACKET] Creating custom ${protocol.toUpperCase()} packet`);

    const packet = createCustomPacket({
      protocol,
      src_ip,
      dst_ip,
      src_port,
      dst_port,
      payload,
      flags
    });

    res.json({
      packet_id: generatePacketId(),
      protocol,
      source: `${src_ip}:${src_port}`,
      destination: `${dst_ip}:${dst_port}`,
      size: payload.length + 40, // Mock header size
      created: new Date().toISOString()
    });

  } catch (error) {
    console.error(`❌ [PACKET] Error creating packet:`, error);
    res.status(500).json({ 
      error: 'Packet creation error', 
      message: error.message 
    });
  }
});

function createCustomPacket(options) {
  // Mock packet creation
  return {
    id: generatePacketId(),
    protocol: options.protocol,
    src: `${options.src_ip}:${options.src_port}`,
    dst: `${options.dst_ip}:${options.dst_port}`,
    payload: options.payload,
    flags: options.flags,
    timestamp: new Date().toISOString()
  };
}

function generatePacketId() {
  return 'pkt_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
}

// Start the server
app.listen(PORT, () => {
  console.log(`📦 [PACKET] Service started on port ${PORT}`);
  console.log(`🔧 [PACKET] Ready to capture and manipulate packets`);
  console.log(`📡 [PACKET] Health check: http://localhost:${PORT}/health`);
});