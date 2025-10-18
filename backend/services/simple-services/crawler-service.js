#!/usr/bin/env node

/**
 * COBRA AI Web Crawler Service - Node.js Implementation
 * Web crawling and content analysis service
 */

const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const cheerio = require('cheerio');

// Node.js File API polyfill for older versions
if (typeof global.File === 'undefined') {
  global.File = class File {
    constructor(fileBits, fileName, options = {}) {
      this.name = fileName;
      this.type = options.type || '';
      this.lastModified = options.lastModified || Date.now();
      this.size = fileBits.reduce((sum, bit) => sum + (bit.length || bit.byteLength || 0), 0);
    }
  };
}

const app = express();
const PORT = process.env.CRAWLER_SERVICE_PORT || 8004;

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'COBRA AI Web Crawler',
    version: '1.0.0-dev',
    capabilities: ['web_crawl', 'content_analysis', 'link_discovery', 'form_analysis'],
    timestamp: new Date().toISOString()
  });
});

// Web crawling endpoint
app.post('/api/crawl/website', async (req, res) => {
  try {
    const { 
      url, 
      max_depth = 2, 
      max_pages = 50, 
      follow_external = false,
      include_assets = false,
      respect_robots = true,
      custom_headers = {}
    } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    console.log(`🕷️ [CRAWLER] Starting crawl for: ${url}`);

    const crawlResults = await performCrawl(url, {
      max_depth,
      max_pages,
      follow_external,
      include_assets,
      respect_robots,
      custom_headers
    });

    console.log(`✅ [CRAWLER] Crawl completed for ${url} - ${crawlResults.pages_crawled} pages found`);
    res.json(crawlResults);

  } catch (error) {
    console.error(`❌ [CRAWLER] Error during crawl:`, error);
    res.status(500).json({ 
      error: 'Crawler error', 
      message: error.message 
    });
  }
});

// Directory discovery endpoint
app.post('/api/crawl/directories', async (req, res) => {
  try {
    const { 
      base_url, 
      wordlist = 'common',
      extensions = ['.php', '.html', '.js', '.txt'],
      threads = 10
    } = req.body;

    if (!base_url) {
      return res.status(400).json({ error: 'Base URL is required' });
    }

    console.log(`📁 [CRAWLER] Starting directory discovery for: ${base_url}`);

    const directories = await discoverDirectories(base_url, {
      wordlist,
      extensions,
      threads
    });

    res.json({
      base_url,
      timestamp: new Date().toISOString(),
      directories_found: directories,
      scan_type: 'directory_discovery'
    });

  } catch (error) {
    console.error(`❌ [CRAWLER] Error during directory discovery:`, error);
    res.status(500).json({ 
      error: 'Directory discovery error', 
      message: error.message 
    });
  }
});

// Form analysis endpoint
app.post('/api/crawl/forms', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    console.log(`📝 [CRAWLER] Analyzing forms for: ${url}`);

    const forms = await analyzeForms(url);

    res.json({
      url,
      timestamp: new Date().toISOString(),
      forms_found: forms
    });

  } catch (error) {
    console.error(`❌ [CRAWLER] Error during form analysis:`, error);
    res.status(500).json({ 
      error: 'Form analysis error', 
      message: error.message 
    });
  }
});

// Technology detection endpoint
app.post('/api/crawl/technologies', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    console.log(`🔍 [CRAWLER] Detecting technologies for: ${url}`);

    const technologies = await detectTechnologies(url);

    res.json({
      url,
      timestamp: new Date().toISOString(),
      technologies_detected: technologies
    });

  } catch (error) {
    console.error(`❌ [CRAWLER] Error during technology detection:`, error);
    res.status(500).json({ 
      error: 'Technology detection error', 
      message: error.message 
    });
  }
});

// Main crawling function
async function performCrawl(startUrl, options) {
  const visited = new Set();
  const toVisit = [{ url: startUrl, depth: 0 }];
  const results = {
    start_url: startUrl,
    timestamp: new Date().toISOString(),
    pages_crawled: 0,
    pages: [],
    links_found: [],
    forms_found: [],
    assets_found: [],
    errors: [],
    crawl_options: options
  };

  const baseUrl = new URL(startUrl);

  while (toVisit.length > 0 && results.pages_crawled < options.max_pages) {
    const { url, depth } = toVisit.shift();

    if (visited.has(url) || depth > options.max_depth) {
      continue;
    }

    visited.add(url);

    try {
      const pageData = await crawlPage(url, options.custom_headers);
      
      results.pages.push({
        url,
        depth,
        status_code: pageData.status_code,
        title: pageData.title,
        content_length: pageData.content ? pageData.content.length : 0,
        links: pageData.links.length,
        forms: pageData.forms.length,
        technologies: pageData.technologies,
        response_time: pageData.response_time
      });

      results.pages_crawled++;

      // Add found links to crawl queue
      for (const link of pageData.links) {
        const linkUrl = resolveUrl(link, url);
        if (linkUrl && shouldFollowLink(linkUrl, baseUrl, options.follow_external) && !visited.has(linkUrl)) {
          toVisit.push({ url: linkUrl, depth: depth + 1 });
          results.links_found.push({
            source: url,
            target: linkUrl,
            text: link.text || '',
            type: link.type || 'internal'
          });
        }
      }

      // Collect forms
      results.forms_found.push(...pageData.forms.map(form => ({
        ...form,
        found_on: url,
        depth
      })));

      // Collect assets if requested
      if (options.include_assets) {
        results.assets_found.push(...pageData.assets.map(asset => ({
          ...asset,
          found_on: url
        })));
      }

    } catch (error) {
      results.errors.push({
        url,
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  return results;
}

// Crawl a single page
async function crawlPage(url, customHeaders = {}) {
  const startTime = Date.now();
  
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'COBRA-AI-Crawler/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        ...customHeaders
      },
      timeout: 10000
    };

    const req = client.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        const response_time = Date.now() - startTime;
        
        try {
          const pageData = parsePageContent(data, url);
          resolve({
            status_code: res.statusCode,
            response_time,
            ...pageData
          });
        } catch (error) {
          reject(error);
        }
      });
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

// Parse page content using cheerio
function parsePageContent(html, baseUrl) {
  const $ = cheerio.load(html);
  
  const pageData = {
    title: $('title').text() || '',
    content: html,
    links: [],
    forms: [],
    assets: [],
    technologies: []
  };

  // Extract links
  $('a[href]').each((i, elem) => {
    const href = $(elem).attr('href');
    const text = $(elem).text().trim();
    if (href) {
      pageData.links.push({
        href,
        text,
        type: href.startsWith('http') ? 'external' : 'internal'
      });
    }
  });

  // Extract forms
  $('form').each((i, elem) => {
    const form = {
      action: $(elem).attr('action') || '',
      method: $(elem).attr('method') || 'GET',
      inputs: [],
      has_file_upload: false
    };

    $(elem).find('input, textarea, select').each((j, input) => {
      const inputData = {
        type: $(input).attr('type') || 'text',
        name: $(input).attr('name') || '',
        id: $(input).attr('id') || '',
        required: $(input).attr('required') !== undefined
      };

      if (inputData.type === 'file') {
        form.has_file_upload = true;
      }

      form.inputs.push(inputData);
    });

    pageData.forms.push(form);
  });

  // Extract assets
  $('img[src], script[src], link[href]').each((i, elem) => {
    const src = $(elem).attr('src') || $(elem).attr('href');
    const tagName = elem.tagName.toLowerCase();
    
    if (src) {
      pageData.assets.push({
        type: tagName,
        src,
        alt: $(elem).attr('alt') || ''
      });
    }
  });

  // Detect technologies
  pageData.technologies = detectTechnologiesFromContent($, html);

  return pageData;
}

// Directory discovery
async function discoverDirectories(baseUrl, options) {
  const commonDirs = [
    'admin', 'administrator', 'login', 'dashboard', 'panel', 'config',
    'backup', 'old', 'test', 'dev', 'staging', 'api', 'v1', 'v2',
    'uploads', 'files', 'assets', 'static', 'images', 'css', 'js',
    'include', 'lib', 'vendor', 'node_modules', '.git', '.svn'
  ];

  const found = [];
  const promises = [];

  for (const dir of commonDirs) {
    for (const ext of ['', ...options.extensions]) {
      const testUrl = `${baseUrl.replace(/\/$/, '')}/${dir}${ext}`;
      promises.push(checkUrl(testUrl));
    }
  }

  const results = await Promise.allSettled(promises);
  
  results.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value.exists) {
      found.push({
        path: result.value.url,
        status_code: result.value.status_code,
        content_length: result.value.content_length
      });
    }
  });

  return found;
}

// Check if URL exists
async function checkUrl(url) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const req = client.request(url, { method: 'HEAD', timeout: 5000 }, (res) => {
      resolve({
        url,
        exists: res.statusCode < 400,
        status_code: res.statusCode,
        content_length: res.headers['content-length'] || 0
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ url, exists: false });
    });

    req.on('error', () => {
      resolve({ url, exists: false });
    });

    req.end();
  });
}

// Analyze forms on a page
async function analyzeForms(url) {
  try {
    const pageData = await crawlPage(url);
    return pageData.forms.map(form => ({
      ...form,
      security_issues: analyzeFormSecurity(form),
      potential_attacks: suggestFormAttacks(form)
    }));
  } catch (error) {
    throw error;
  }
}

// Analyze form security
function analyzeFormSecurity(form) {
  const issues = [];

  if (form.method.toUpperCase() === 'GET' && form.inputs.some(i => i.type === 'password')) {
    issues.push('Password field in GET form');
  }

  if (!form.inputs.some(i => i.type === 'hidden' && i.name.includes('csrf'))) {
    issues.push('No CSRF protection detected');
  }

  if (form.has_file_upload) {
    issues.push('File upload form - check for upload restrictions');
  }

  return issues;
}

// Suggest form attacks
function suggestFormAttacks(form) {
  const attacks = [];

  if (form.inputs.some(i => i.type === 'text' || i.type === 'textarea')) {
    attacks.push('SQL Injection', 'XSS', 'Command Injection');
  }

  if (form.has_file_upload) {
    attacks.push('File Upload Attack', 'Path Traversal');
  }

  if (form.inputs.some(i => i.type === 'password')) {
    attacks.push('Brute Force', 'Credential Stuffing');
  }

  return attacks;
}

// Detect technologies from page content
function detectTechnologiesFromContent($, html) {
  const technologies = [];

  // Check meta tags
  $('meta[name="generator"]').each((i, elem) => {
    technologies.push({
      name: $(elem).attr('content'),
      type: 'CMS/Framework',
      confidence: 0.9
    });
  });

  // Check for common frameworks
  if (html.includes('wp-content') || html.includes('wordpress')) {
    technologies.push({ name: 'WordPress', type: 'CMS', confidence: 0.8 });
  }

  if (html.includes('drupal') || $('body').hasClass('html')) {
    technologies.push({ name: 'Drupal', type: 'CMS', confidence: 0.7 });
  }

  if (html.includes('joomla')) {
    technologies.push({ name: 'Joomla', type: 'CMS', confidence: 0.8 });
  }

  // Check for JavaScript frameworks
  if (html.includes('react') || html.includes('React')) {
    technologies.push({ name: 'React', type: 'JavaScript Framework', confidence: 0.6 });
  }

  if (html.includes('angular') || html.includes('ng-')) {
    technologies.push({ name: 'Angular', type: 'JavaScript Framework', confidence: 0.7 });
  }

  if (html.includes('vue') || html.includes('Vue')) {
    technologies.push({ name: 'Vue.js', type: 'JavaScript Framework', confidence: 0.6 });
  }

  return technologies;
}

// Utility functions
function resolveUrl(link, baseUrl) {
  try {
    if (typeof link === 'string') {
      return new URL(link, baseUrl).href;
    } else if (link.href) {
      return new URL(link.href, baseUrl).href;
    }
    return null;
  } catch {
    return null;
  }
}

function shouldFollowLink(linkUrl, baseUrl, followExternal) {
  try {
    const link = new URL(linkUrl);
    const base = new URL(baseUrl.href || baseUrl);
    
    if (followExternal) {
      return true;
    }
    
    return link.hostname === base.hostname;
  } catch {
    return false;
  }
}

// Start the server
app.listen(PORT, () => {
  console.log(`🕷️ [CRAWLER] Service started on port ${PORT}`);
  console.log(`🌐 [CRAWLER] Ready to crawl websites`);
  console.log(`📡 [CRAWLER] Health check: http://localhost:${PORT}/health`);
});