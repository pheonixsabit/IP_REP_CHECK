const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');
const tls = require('tls');

function loadLocalEnv() {
  const envFile = path.join(__dirname, '.env');
  if (!fs.existsSync(envFile)) return;
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || match[1] in process.env) continue;
    const value = match[2].replace(/^(["'])(.*)\1$/, '$2');
    process.env[match[1]] = value;
  }
}

loadLocalEnv();

// Configure secrets and deployment settings through environment variables.
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || '';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const ABUSEIPDB_MAX_AGE_DAYS = 365;
// Proxy settings come from the setup page and are kept in memory only.
let proxySettings = { enabled: false, host: '', port: 8080, username: '', password: '' };
const HTTPS_PORT = Number(process.env.PORT || 3443);
const HTTPS_HOST = process.env.HOST || '0.0.0.0';
const CERT_DIR = process.env.CERT_DIR || path.join(__dirname, 'certs');
const HTTPS_KEY_FILE = process.env.TLS_KEY_FILE || path.join(CERT_DIR, 'server.key');
const HTTPS_CERT_FILE = process.env.TLS_CERT_FILE || path.join(CERT_DIR, 'server.crt');
const CORPORATE_CA_FILE = process.env.CORPORATE_CA_FILE || '';
const CORPORATE_PROXY_INSECURE_TLS = process.env.CORPORATE_PROXY_INSECURE_TLS === 'true';
const corporateCA = CORPORATE_CA_FILE ? fs.readFileSync(CORPORATE_CA_FILE) : null;
const trustedCAs = corporateCA ? [...tls.rootCertificates, corporateCA] : undefined;
const rsaKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, 'LOG');
const LOG_FILE = path.join(LOG_DIR, 'app.log');
const QUOTA_FILE = path.join(LOG_DIR, 'abuseipdb-quota.json');
const ABUSEIPDB_DAILY_LIMIT = 500;
let abuseIpdbUsage = { day: '', sent: 0 };

fs.mkdirSync(LOG_DIR, { recursive: true });
try {
  const savedUsage = JSON.parse(fs.readFileSync(QUOTA_FILE, 'utf8'));
  if (typeof savedUsage.day === 'string' && Number.isInteger(savedUsage.sent) && savedUsage.sent >= 0) abuseIpdbUsage = savedUsage;
} catch { /* Start a fresh counter when no valid saved quota exists. */ }
// made with AI
// directed by
// Jahid Hossain Sabit

function log(level, message) {
  const line = `${new Date().toISOString()} [${level}] ${message}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line, 'utf8');
  } catch (error) {
    process.stderr.write(`${new Date().toISOString()} [ERROR] Unable to write application log: ${error.message}\n`);
  }
  if (level === 'ERROR') console.error(message);
  else console.log(message);
}

function currentQuota() {
  const day = new Date().toISOString().slice(0, 10);
  if (abuseIpdbUsage.day !== day) abuseIpdbUsage = { day, sent: 0 };
  return { sent: abuseIpdbUsage.sent, limit: ABUSEIPDB_DAILY_LIMIT, remaining: ABUSEIPDB_DAILY_LIMIT - abuseIpdbUsage.sent };
}

function reserveAbuseIpdbRequest() {
  const quota = currentQuota();
  if (quota.remaining <= 0) return false;
  abuseIpdbUsage.sent += 1;
  try {
    fs.writeFileSync(QUOTA_FILE, JSON.stringify(abuseIpdbUsage), 'utf8');
  } catch (error) {
    log('ERROR', `Unable to persist AbuseIPDB quota: ${error.message}`);
  }
  return true;
}

class CorporateProxyAgent extends https.Agent {
  createConnection(options, callback) {
    const proxyHeaders = {};
    if (proxySettings.username && proxySettings.password) {
      proxyHeaders['Proxy-Authorization'] = `Basic ${Buffer.from(`${proxySettings.username}:${proxySettings.password}`).toString('base64')}`;
    }
    const proxyRequest = http.request({
      host: proxySettings.host,
      port: proxySettings.port,
      method: 'CONNECT',
      path: `${options.host}:${options.port || 443}`,
      headers: proxyHeaders,
    });
    proxyRequest.once('connect', (proxyResponse, socket, head) => {
      if (proxyResponse.statusCode !== 200) {
        socket.destroy();
        callback(new Error(`Corporate proxy refused the connection (${proxyResponse.statusCode}).`));
        return;
      }
      if (head.length) socket.unshift(head);
      const secureSocket = tls.connect({ socket, servername: options.servername || options.host, ca: trustedCAs, rejectUnauthorized: !CORPORATE_PROXY_INSECURE_TLS });
      secureSocket.once('secureConnect', () => callback(null, secureSocket));
      secureSocket.once('error', callback);
    });
    proxyRequest.once('error', callback);
    proxyRequest.end();
  }
}

const corporateProxyAgent = new CorporateProxyAgent();
const root = __dirname;
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function send(res, status, body, contentType = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
  res.end(body);
}

function requestJson(hostname, requestPath, headers) {
  return new Promise((resolve, reject) => {
    const upstream = https.request({ hostname, path: requestPath, method: 'GET', headers: { Accept: 'application/json', ...headers }, agent: proxySettings.enabled ? corporateProxyAgent : undefined }, upstreamRes => {
      let body = '';
      upstreamRes.setEncoding('utf8');
      upstreamRes.on('data', chunk => body += chunk);
      upstreamRes.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if ((upstreamRes.statusCode || 500) >= 400) return reject(new Error(parsed.errors?.[0]?.detail || parsed.error?.message || `${hostname} returned HTTP ${upstreamRes.statusCode}.`));
          resolve(parsed);
        } catch { reject(new Error(`Invalid response from ${hostname}.`)); }
      });
    });
    upstream.once('error', reject);
    upstream.end();
  });
}

function probeHttps(hostname, requestPath, headers = {}) {
  return new Promise(resolve => {
    const started = Date.now();
    const probe = https.request({ hostname, path: requestPath, method: 'GET', headers: { Accept: 'application/json', ...headers }, agent: proxySettings.enabled ? corporateProxyAgent : undefined }, response => {
      response.resume();
      response.once('end', () => resolve({ ok: true, status: response.statusCode || 0, latencyMs: Date.now() - started }));
    });
    probe.once('error', error => resolve({ ok: false, error: error.message, latencyMs: Date.now() - started }));
    probe.setTimeout(10000, () => probe.destroy(new Error('Connection timed out.')));
    probe.end();
// made with AI
// directed by
// Jahid Hossain Sabit
  });
}

const abuseIpdbCategories = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
  6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam',
  12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
  18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host', 21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
};

function abuseReports(data) {
  return (data.reports || []).map(report => ({
    reportedAddress: data.ipAddress || '',
    categories: (report.categories || []).map(category => abuseIpdbCategories[category] || `Category ${category}`),
    reportedAt: report.reportedAt || '',
    countryCode: report.reporterCountryCode || '',
  })).filter(report => report.categories.length);
}

function abuseSummary(data) {
  const totalReports = data.totalReports ?? data.total_reports;
  const distinctReporters = data.numDistinctUsers ?? data.distinctReporters ?? data.num_distinct_users;
  return {
    totalReports: Number(totalReports ?? data.reports?.length ?? 0),
    distinctReporters: Number(distinctReporters ?? 0),
  };
}

function virusTotalVendors(data) {
  const analyses = data.data?.attributes?.last_analysis_results || {};
  return Object.values(analyses)
    .filter(analysis => ['malicious', 'suspicious'].includes(analysis.category))
    .map(analysis => ({ vendor: analysis.engine_name || 'Unknown vendor', category: analysis.category, result: analysis.result || '' }))
    .sort((first, second) => first.vendor.localeCompare(second.vendor));
}

function virusTotalCommunicatingFiles(data) {
  return (data.data || [])
    .map(file => file.attributes?.meaningful_name || file.attributes?.sha256 || file.id)
    .filter(Boolean);
}

function virusTotalUrlId(value) {
  return Buffer.from(value).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const requestHandler = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/healthz' && req.method === 'GET') return send(res, 200, JSON.stringify({ status: 'ok' }));
  if (url.pathname === '/api/quota' && req.method === 'GET') return send(res, 200, JSON.stringify({ quota: currentQuota() }));
  if (url.pathname === '/api/proxy-settings' && req.method === 'GET') {
    return send(res, 200, JSON.stringify({ enabled: proxySettings.enabled, host: proxySettings.host, port: proxySettings.port, username: proxySettings.username, hasPassword: Boolean(proxySettings.password) }));
  }
  if (url.pathname === '/api/proxy-settings' && req.method === 'PUT') {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const settings = JSON.parse(body);
        const enabled = Boolean(settings.enabled);
        const host = String(settings.host || '').trim();
        const port = Number(settings.port || 8080);
        if (enabled && (!host || !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('Enter a valid proxy host and port.');
        let password = enabled ? String(settings.password || '') : '';
        if (settings.encryptedPassword) password = crypto.privateDecrypt({ key: rsaKeys.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'SHA-256' }, Buffer.from(settings.encryptedPassword, 'base64')).toString('utf8');
        proxySettings = { enabled, host: enabled ? host : '', port: enabled ? port : 8080, username: enabled ? String(settings.username || '').trim() : '', password };
        send(res, 200, JSON.stringify({ enabled: proxySettings.enabled }));
      } catch (error) { send(res, 400, JSON.stringify({ error: error.message || 'Invalid proxy settings.' })); }
    });
    return;
  }
  if (url.pathname === '/api/public-key' && req.method === 'GET') return send(res, 200, JSON.stringify({ publicKey: rsaKeys.publicKey }));
  if (url.pathname === '/api/resolve' && req.method === 'GET') {
    const urlParam = url.searchParams.get('url');
    const hostParam = url.searchParams.get('host');
    log('INFO', `/api/resolve called; url=${urlParam || ''} host=${hostParam || ''}`);
    try {
      let target;
      if (urlParam) {
        target = new URL(urlParam);
        if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || !target.hostname) throw new Error('Only HTTP and HTTPS URLs without credentials are supported.');
      } else if (hostParam) {
        // Accept a bare hostname (e.g. example.com) and treat it as an http URL for DNS resolution
        if (!/^[A-Za-z0-9.-]{1,253}$/.test(hostParam) || hostParam.startsWith('-') || hostParam.endsWith('-')) throw new Error('Invalid hostname.');
        target = new URL(`http://${hostParam}`);
      } else {
        throw new Error('Provide a `url` or `host` query parameter.');
      }
      const lookupStart = Date.now();
      const records = await dns.lookup(target.hostname, { all: true, verbatim: true });
      const addresses = records.map(result => result.address).filter(address => net.isIP(address));
      log('INFO', `/api/resolve result for ${target.hostname}: ${addresses.length} addresses in ${Date.now() - lookupStart}ms`);
      if (!addresses.length) return send(res, 404, JSON.stringify({ error: 'The hostname did not resolve to an IP address.' }));
      return send(res, 200, JSON.stringify({ url: target.href, addresses: [...new Set(addresses)] }));
    } catch (error) {
      log('ERROR', `/api/resolve error: ${error.message}`);
      const message = error.code === 'ENOTFOUND' ? 'The hostname could not be resolved.' : error.message || 'Invalid host or URL.';
      return send(res, 400, JSON.stringify({ error: message }));
    }
  }
  if (url.pathname === '/api/connectivity' && req.method === 'GET') {
    Promise.all([
      probeHttps('example.com', '/'),
      probeHttps('api.abuseipdb.com', '/', ABUSEIPDB_API_KEY ? { Key: ABUSEIPDB_API_KEY } : {}),
      probeHttps('www.virustotal.com', '/', VIRUSTOTAL_API_KEY ? { 'x-apikey': VIRUSTOTAL_API_KEY } : {}),
// made with AI
// directed by
// Jahid Hossain Sabit
    ]).then(([internet, abuseipdb, virustotal]) => send(res, 200, JSON.stringify({ proxy: proxySettings.enabled, testedAt: new Date().toISOString(), checks: { internet, abuseipdb, virustotal } })));
    return;
  }
  if (url.pathname === '/api/check') {
    if (!ABUSEIPDB_API_KEY) return send(res, 503, JSON.stringify({ errors: [{ detail: 'The server is missing ABUSEIPDB_API_KEY configuration.' }] }));
    const ipAddress = url.searchParams.get('ipAddress');
    const targetUrl = url.searchParams.get('targetUrl');
    if (!ipAddress) return send(res, 400, JSON.stringify({ errors: [{ detail: 'An IP address is required.' }] }));
    if (!reserveAbuseIpdbRequest()) return send(res, 429, JSON.stringify({ errors: [{ detail: 'The daily AbuseIPDB request limit has been reached.' }], quota: currentQuota() }));
    const abuseRequest = requestJson('api.abuseipdb.com', `/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=${ABUSEIPDB_MAX_AGE_DAYS}&verbose=true`, { Key: ABUSEIPDB_API_KEY });
    const virusTotalRequest = VIRUSTOTAL_API_KEY ? requestJson('www.virustotal.com', `/api/v3/ip_addresses/${encodeURIComponent(ipAddress)}`, { 'x-apikey': VIRUSTOTAL_API_KEY }) : Promise.resolve(null);
    const communicatingFilesRequest = VIRUSTOTAL_API_KEY ? requestJson('www.virustotal.com', `/api/v3/ip_addresses/${encodeURIComponent(ipAddress)}/communicating_files?limit=40`, { 'x-apikey': VIRUSTOTAL_API_KEY }) : Promise.resolve(null);
    const virusTotalUrlRequest = VIRUSTOTAL_API_KEY && targetUrl ? requestJson('www.virustotal.com', `/api/v3/urls/${virusTotalUrlId(targetUrl)}`, { 'x-apikey': VIRUSTOTAL_API_KEY }) : Promise.resolve(null);
    Promise.allSettled([abuseRequest, virusTotalRequest, communicatingFilesRequest, virusTotalUrlRequest]).then(([abuse, virusTotal, communicatingFiles, virusTotalUrl]) => {
      if (abuse.status === 'rejected') return send(res, 502, JSON.stringify({ errors: [{ detail: `Could not reach AbuseIPDB through the corporate proxy: ${abuse.reason.message}` }], quota: currentQuota() }));
      const response = { ...abuse.value, virusTotal: null };
      if (virusTotal.status === 'fulfilled' && virusTotal.value) {
        const stats = virusTotal.value.data?.attributes?.last_analysis_stats || {};
        const vtIsp = virusTotal.value.data?.attributes?.as_owner || '';
        response.virusTotal = {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          isp: vtIsp,
          vendors: virusTotalVendors(virusTotal.value),
          threatTags: virusTotal.value.data?.attributes?.tags || [],
          threatNames: virusTotalUrl.status === 'fulfilled' && virusTotalUrl.value ? virusTotalUrl.value.data?.attributes?.threat_names || [] : virusTotal.value.data?.attributes?.threat_names || [],
          communicatingFiles: communicatingFiles.status === 'fulfilled' && communicatingFiles.value ? virusTotalCommunicatingFiles(communicatingFiles.value) : [],
        };
      } else if (VIRUSTOTAL_API_KEY) response.virusTotal = { error: virusTotal.reason?.message || 'VirusTotal lookup failed.' };
      response.abuseReports = abuseReports(abuse.value.data || {});
      response.abuseSummary = abuseSummary(abuse.value.data || {});
      response.quota = currentQuota();
      send(res, 200, JSON.stringify(response));
    });
    return;
  }
  const requested = url.pathname === '/' ? '/index.html' : url.pathname;
  const file = path.normalize(path.join(root, requested));
  if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
  send(res, 200, fs.readFileSync(file), types[path.extname(file)] || 'application/octet-stream');
};

if (!fs.existsSync(HTTPS_KEY_FILE) || !fs.existsSync(HTTPS_CERT_FILE)) {
  log('ERROR', `HTTPS certificate files are required: ${HTTPS_KEY_FILE} and ${HTTPS_CERT_FILE}`);
  log('ERROR', 'Create a local certificate (see README.md), then start the server again.');
  process.exit(1);
}
const server = https.createServer({ key: fs.readFileSync(HTTPS_KEY_FILE), cert: fs.readFileSync(HTTPS_CERT_FILE) }, requestHandler);
server.on('error', error => {
  log('ERROR', `Unable to start HTTPS server: ${error.message}`);
  process.exitCode = 1;
});
server.listen(HTTPS_PORT, HTTPS_HOST, () => log('INFO', `IP Reputation Checker running at https://${HTTPS_HOST}:${HTTPS_PORT}`));
