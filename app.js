const API_URL = '/api/check';
const state = { results: [], destinations: {}, emailMode: 'flagged', resultSort: { key: 'default', direction: 'asc' } };
const $ = (id) => document.getElementById(id);
const savedTheme = localStorage.getItem('ip-checker-theme');
if (savedTheme === 'dark') document.documentElement.dataset.theme = 'dark';

function normalizeISP(isp) {
  if (!isp) return '';
  return isp.toLowerCase()
    .split(/[/,|]/) // Split by common separators
    .map(part => part.trim())
    .filter(part => part.length > 0 && part.length > 2) // Remove short parts (like "S.A", "Ltd")
    .map(part => part.replace(/\b(s\.?a|ltd|inc|llc|gmbh|sa|co|corp|company|customer\s+assignment)\b/gi, '').trim())
    .filter(Boolean)
    .join(' ');
}

function ispNamesMatch(isp1, isp2) {
  if (!isp1 || !isp2) return false;
  const norm1 = normalizeISP(isp1);
  const norm2 = normalizeISP(isp2);
  if (!norm1 || !norm2) return isp1.toLowerCase() === isp2.toLowerCase();
  // Exact match after normalization
  if (norm1 === norm2) return true;
  // Check if one is contained in the other (significant overlap)
  const words1 = norm1.split(/\s+/);
  const words2 = norm2.split(/\s+/);
  const commonWords = words1.filter(w => words2.includes(w)).length;
  const minWords = Math.min(words1.length, words2.length);
  // If at least 50% of words match, consider them the same
  return minWords > 0 && commonWords / minWords >= 0.5;
}

function showToast(message) { const toast = $('toast'); toast.textContent = message; toast.classList.add('show'); clearTimeout(showToast.timer); showToast.timer = setTimeout(() => toast.classList.remove('show'), 3000); }
function updateThemeToggle() { const dark = document.documentElement.dataset.theme === 'dark'; $('themeToggle').innerHTML = `<span aria-hidden="true">${dark ? '☀' : '☾'}</span> ${dark ? 'Day mode' : 'Night mode'}`; $('themeToggle').setAttribute('aria-pressed', String(dark)); }
function toggleTheme() { const dark = document.documentElement.dataset.theme !== 'dark'; document.documentElement.dataset.theme = dark ? 'dark' : 'light'; localStorage.setItem('ip-checker-theme', dark ? 'dark' : 'light'); updateThemeToggle(); }
function toggleProxyFields() { $('proxyFields').hidden = !$('useProxy').checked; }
function showView(viewId) { ['proxyView', 'checkerView', 'loadingView', 'resultsView', 'connectivityView', 'emailView'].forEach(id => { $(id).hidden = id !== viewId; }); window.scrollTo({ top: 0, behavior: 'smooth' }); }
async function saveProxySettings() {
  const enabled = $('useProxy').checked;
  const settings = { enabled, host: $('proxyHost').value.trim(), port: $('proxyPort').value, username: $('proxyUsername').value.trim() };
  try {
    if (enabled && $('proxyPassword').value) {
      const keyResponse = await fetch('/api/public-key');
      const { publicKey } = await keyResponse.json();
      const pemBody = publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, '');
      const binary = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
      const cryptoKey = await window.crypto.subtle.importKey('spki', binary.buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      const encrypted = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, new TextEncoder().encode($('proxyPassword').value));
// made with AI
// directed by
// Jahid Hossain Sabit
      settings.encryptedPassword = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }
    const response = await fetch('/api/proxy-settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to save proxy settings.');
    showView('connectivityView');
    loadQuota();
    runConnectivityCheck();
  } catch (error) { showToast(error.message); }
}
function updateQuota(quota) { if (quota) $('quotaCounter').textContent = `${quota.sent} / ${quota.limit} requests sent`; }
async function loadQuota() { try { const response = await fetch('/api/quota', { headers: { Accept: 'application/json' } }); const data = await response.json(); updateQuota(data.quota); } catch { /* The counter remains at its last known value. */ } }
function getIPs(value) { return [...new Set(value.split(/[\s,;]+/).map(v => v.trim()).filter(Boolean))]; }
function isIP(value) {
  if (value.includes(':')) return /^[0-9a-fA-F:]+$/.test(value) && value.split(':').length >= 3;
  const parts = value.split('.'); return parts.length === 4 && parts.every(p => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255 && p.length <= 3);
}
function isURL(value) { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && Boolean(url.hostname) && !url.username && !url.password; } catch { return false; } }
function stripPathSuffix(value) {
  if (!value) return value;
  return value.split(/[/?#]/)[0].trim();
}
function isBareHostPath(value) {
  if (!value || value.includes('://')) return false;
  const host = stripPathSuffix(value);
  if (!host || host === '.' || host === '/') return false;
  return /^[A-Za-z0-9.-]{1,253}$/.test(host) && host.split('.').length >= 2 && !/^[0-9.]+$/.test(host);
}
function normalizeTarget(value) {
  const host = stripPathSuffix(value);
  if (isBareHostPath(value)) return `https://${host}`;
  return isURL(value) ? new URL(value).origin : value;
}
function displayTarget(value) {
  const host = stripPathSuffix(value);
  if (isBareHostPath(value)) return host;
  if (!isURL(value)) return value;
  const url = new URL(value);
  return url.hostname;
}
function isHost(value) {
  const host = stripPathSuffix(value);
  if (isIP(host)) return false;
  try { new URL(value); return false; } catch {}
  // Basic hostname validation: letters, numbers, dots and hyphens, at least one dot
  return /^[A-Za-z0-9.-]{1,253}$/.test(host) && host.split('.').length >= 2 && !/^[0-9.]+$/.test(host);
}
function ipToBigInt(value) {
  if (!value.includes(':')) return value.split('.').reduce((result, part) => (result << 8n) + BigInt(part), 0n);
  let address = value;
  if (address.includes('.')) { const parts = address.split(':'); const ipv4 = parts.pop().split('.').map(Number); parts.push(((ipv4[0] << 8) | ipv4[1]).toString(16), ((ipv4[2] << 8) | ipv4[3]).toString(16)); address = parts.join(':'); }
  const halves = address.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.reduce((result, group) => (result << 16n) + BigInt(`0x${group}`), 0n);
}
function bigIntToIP(value, version) {
  if (version === 4) return [24n,16n,8n,0n].map(shift => Number((value >> shift) & 255n)).join('.');
  return Array.from({ length: 8 }, (_, index) => ((value >> BigInt((7 - index) * 16)) & 65535n).toString(16).padStart(4, '0')).join(':');
}
function expandCIDR(value) {
  const [address, prefixText] = value.split('/');
  if (!address || !/^\d+$/.test(prefixText) || !isIP(address)) return null;
  const version = address.includes(':') ? 6 : 4;
  const bits = version === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (prefix > bits) return null;
  const count = 2n ** BigInt(bits - prefix);
  if (count > 256n) throw new Error('CIDR ranges are limited to 256 addresses.');
  const base = ipToBigInt(address) & (((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix));
  return Array.from({ length: Number(count) }, (_, index) => bigIntToIP(base + BigInt(index), version));
}
function expandInput(value) {
  const normalized = stripPathSuffix(value);
  if (isURL(value)) return [value];
  if (value.includes('/')) {
    if (isBareHostPath(value)) return [normalized];
    return expandCIDR(value);
  }
  return isIP(normalized) || isHost(normalized) ? [normalized] : null;
}
function scoreClass(score) { if (score === 0) return 'clean'; if (score < 25) return 'low'; if (score < 75) return 'suspicious'; return 'high'; }
function scoreStatus(score) { if (score === 0) return 'Clean'; if (score < 25) return 'Low risk'; if (score < 75) return 'Suspicious'; return 'High risk'; }
function weight(score) { if (score >= 3) return 3; if (score === 2) return 2; if (score === 1) return 1; return 0; }
function abuseWeight(score) { if (score === 100) return 3; if (score >= 50) return 2; if (score > 0) return 1; return 0; }
function verdictFromTotal(total) { if (total >= 6) return 'MAL'; if (total >= 4) return 'SUSP'; return 'CLEAN'; }
function verdictLabel(verdict) { return ({ MAL: 'Malicious', SUSP: 'Suspicious', CLEAN: 'Clean' })[verdict]; }
function isTrustedResult(result) {
  const provider = `${result.isp || ''} ${result.abuseIsp || ''} ${result.vtIsp || ''} ${result.domain || ''}`.toLowerCase();
  return provider.includes('google') || (provider.includes('microsoft') && !provider.includes('azure')) || provider.includes('oracle');
}
function resultNotes(result) {
  const providerBoth = `${result.isp || ''} ${result.domain || ''}`.toLowerCase();
  const providerAbuse = `${result.abuseIsp || ''} ${result.domain || ''}`.toLowerCase();
  const providerVT = `${result.vtIsp || ''} ${result.domain || ''}`.toLowerCase();
  const provider = providerBoth || providerAbuse || providerVT;
// made with AI
// directed by
// Jahid Hossain Sabit
  const notes = [];
  if (isTrustedResult(result) && (result.finalVerdict === 'SUSP' || result.finalVerdict === 'MAL')) notes.push('Trusted provider — do not block');
  if ((result.country || '').toUpperCase() === 'BD' && result.totalWeight >= 4) notes.push('Bangladesh IP with high score — reconfirm');
  if (result.abuseIsp && result.vtIsp && !ispNamesMatch(result.abuseIsp, result.vtIsp)) notes.push('ISP names differ between sources');
  return notes.join(' · ');
}
function escapeHTML(value = '') { return String(value).replace(/[&<>'"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;', "'":'&#39;','"':'&quot;' }[c])); }
function reportButton(result) { return result.finalVerdict === 'MAL' ? `<button class="report-button" type="button" data-report="${state.results.indexOf(result)}">View report</button>` : '—'; }
const resultSorters = {
  target: result => result.source || result.ipAddress || '',
  ipAddress: result => result.ipAddress || '',
  country: result => result.country || '',
  usageType: result => result.usageType || '',
  isp: result => result.isp || '',
  domain: result => result.domain || '',
  abuseConfidenceScore: result => result.abuseConfidenceScore ?? -1,
  virusTotal: result => (result.vtMalicious || 0) * 1000 + (result.vtSuspicious || 0),
  finalVerdict: result => ({ MAL: 3, SUSP: 2, CLEAN: 1 })[result.finalVerdict] || 0,
  note: result => result.note || '',
};
function compareResults(first, second) {
  const { key, direction } = state.resultSort;
  if (key === 'default') return Number(Boolean(first.error)) - Number(Boolean(second.error));
  const firstValue = resultSorters[key](first);
  const secondValue = resultSorters[key](second);
  const comparison = typeof firstValue === 'number' && typeof secondValue === 'number'
    ? firstValue - secondValue
    : String(firstValue).localeCompare(String(secondValue), undefined, { numeric: true, sensitivity: 'base' });
  return (comparison || Number(Boolean(first.error)) - Number(Boolean(second.error))) * (direction === 'desc' ? -1 : 1);
}
function renderSortState() {
  document.querySelectorAll('[data-sort-key]').forEach(header => {
    const active = header.dataset.sortKey === state.resultSort.key;
    header.setAttribute('aria-sort', active ? (state.resultSort.direction === 'asc' ? 'ascending' : 'descending') : 'none');
    const button = header.querySelector('button');
    if (button) button.querySelector('.sort-indicator').textContent = active ? (state.resultSort.direction === 'asc' ? '↑' : '↓') : '↕';
  });
}
function sortResults(key) {
  if (state.resultSort.key === key) state.resultSort.direction = state.resultSort.direction === 'asc' ? 'desc' : 'asc';
  else state.resultSort = { key, direction: 'asc' };
  renderResults();
}
function renderResults() {
  const body = $('resultsBody');
  const orderedResults = [...state.results].sort(compareResults);
  body.innerHTML = orderedResults.map(r => r.error ? `<tr><td class="ip">${escapeHTML(r.source || r.ipAddress)}</td><td>${escapeHTML(r.ipAddress || '—')}</td><td colspan="8">—</td><td><span class="status error">${escapeHTML(r.error)}</span></td></tr>` : `<tr><td class="ip">${escapeHTML(r.source || r.ipAddress)}</td><td>${escapeHTML(r.ipAddress)}</td><td>${escapeHTML(r.country || '—')}</td><td>${escapeHTML(r.usageType || '—')}</td><td>${escapeHTML(r.isp || '—')}</td><td>${escapeHTML(r.domain || '—')}</td><td><span class="score ${scoreClass(r.abuseConfidenceScore)}">${r.abuseConfidenceScore}</span></td><td>${r.virusTotalError ? `<span class="status error">${escapeHTML(r.virusTotalError)}</span>` : r.vtEnabled ? `<span class="status">${r.vtMalicious} malicious / ${r.vtSuspicious} suspicious</span>` : 'Not configured'}</td><td>${r.finalVerdict ? `<span class="verdict ${r.finalVerdict.toLowerCase()}">${verdictLabel(r.finalVerdict)} (${r.totalWeight})</span>` : 'Not configured'}</td><td>${r.note ? `<span class="note">${escapeHTML(r.note)}</span>` : '—'}</td><td>${reportButton(r)}</td></tr>`).join('');
  renderSortState();
  const successful = state.results.filter(r => !r.error).length;
  $('resultSummary').textContent = `${successful} of ${state.results.length} address${state.results.length === 1 ? '' : 'es'} checked successfully.`;
}
async function checkIP(ip, source = ip, targetType = 'ip', targetUrl = '') {
  const urlParameter = targetUrl ? `&targetUrl=${encodeURIComponent(targetUrl)}` : '';
  const response = await fetch(`${API_URL}?ipAddress=${encodeURIComponent(ip)}${urlParameter}`, { headers: { Accept: 'application/json' } });
  const data = await response.json().catch(() => ({}));
  updateQuota(data.quota);
  if (!response.ok) throw new Error(data.errors?.[0]?.detail || `API error (${response.status})`);
  const payload = data; const d = payload.data;
  const vtEnabled = Boolean(payload.virusTotal) && !payload.virusTotal?.error;
  const vtMalicious = payload.virusTotal?.malicious || 0;
  const vtSuspicious = payload.virusTotal?.suspicious || 0;
  const vtIsp = payload.virusTotal?.isp || '';
  const abuseIsp = d.isp || '';
  const ispMatch = ispNamesMatch(abuseIsp, vtIsp);
  const ispDisplay = ispMatch ? abuseIsp : (abuseIsp && vtIsp ? `${abuseIsp} / ${vtIsp}` : abuseIsp || vtIsp);
  const totalWeight = vtEnabled ? abuseWeight(d.abuseConfidenceScore) + weight(vtMalicious) + weight(vtSuspicious) : 0;
  const result = { source, targetType, ipAddress: d.ipAddress, country: d.countryName || d.countryCode, usageType: d.usageType, isp: ispDisplay, abuseIsp, vtIsp, domain: d.domain, abuseConfidenceScore: d.abuseConfidenceScore, abuseWeight: abuseWeight(d.abuseConfidenceScore), abuseReports: payload.abuseReports || [], totalAbuseReports: payload.abuseSummary?.totalReports || 0, distinctAbuseReporters: payload.abuseSummary?.distinctReporters || 0, vtEnabled, vtMalicious, vtSuspicious, vtVendors: payload.virusTotal?.vendors || [], vtThreatTags: payload.virusTotal?.threatTags || [], vtThreatNames: payload.virusTotal?.threatNames || [], vtCommunicatingFiles: payload.virusTotal?.communicatingFiles || [], vtMaliciousWeight: weight(vtMalicious), vtSuspiciousWeight: weight(vtSuspicious), virusTotalError: payload.virusTotal?.error, totalWeight, finalVerdict: vtEnabled ? verdictFromTotal(totalWeight) : '' };
  result.note = resultNotes(result);
  return result;
}
function openReport(result) {
  const abuseCategories = [...new Set(result.abuseReports.flatMap(report => report.categories || []))];
  const vendors = result.vtVendors || [];
  const cidrResults = state.results.filter(item => item.targetType === 'cidr' && item.source === result.source && !item.error);
  const reportedCIDRResults = cidrResults.filter(item => item.totalAbuseReports > 0);
  const requestedSection = result.targetType === 'cidr'
    ? `<h3>Reported IP addresses (${reportedCIDRResults.length})</h3>${reportedCIDRResults.length ? `<ul>${reportedCIDRResults.map(item => `<li>${escapeHTML(item.ipAddress)}</li>`).join('')}</ul>` : '<p class="empty-state">No reported IP addresses returned.</p>'}`
    : result.targetType === 'url'
      ? `<h3>VirusTotal threat names</h3>${result.vtThreatNames.length ? `<ul>${result.vtThreatNames.map(name => `<li>${escapeHTML(name)}</li>`).join('')}</ul>` : '<p class="empty-state">No VirusTotal threat names returned.</p>'}`
      : `<h3>AbuseIPDB summary</h3><ul><li>Total abuse reports: ${escapeHTML(result.totalAbuseReports)}</li><li>Distinct reporting users: ${escapeHTML(result.distinctAbuseReporters)}</li></ul><h3>VirusTotal communicating files</h3>${result.vtCommunicatingFiles.length ? `<ul>${result.vtCommunicatingFiles.map(file => `<li>${escapeHTML(file)}</li>`).join('')}</ul>` : '<p class="empty-state">No communicating files returned.</p>'}<h3>VirusTotal threat tags</h3>${result.vtThreatTags.length ? `<ul>${result.vtThreatTags.map(tag => `<li>${escapeHTML(tag)}</li>`).join('')}</ul>` : '<p class="empty-state">No threat tags returned.</p>'}`;
  $('reportTitle').textContent = `Threat report: ${result.source || result.ipAddress}`;
  $('reportBody').innerHTML = `<p class="report-verdict"><strong>${escapeHTML(verdictLabel(result.finalVerdict))}</strong> · ${escapeHTML(result.ipAddress)}</p>${requestedSection}<h3>AbuseIPDB categories</h3>${abuseCategories.length ? `<ul>${abuseCategories.map(category => `<li>${escapeHTML(category)}</li>`).join('')}</ul>` : '<p class="empty-state">No AbuseIPDB report categories returned.</p>'}<h3>VirusTotal vendors</h3>${vendors.length ? `<ul>${vendors.map(item => `<li><strong>${escapeHTML(item.vendor)}</strong> — ${escapeHTML(item.category)}${item.result ? ` (${escapeHTML(item.result)})` : ''}</li>`).join('')}</ul>` : '<p class="empty-state">No VirusTotal vendor detections returned.</p>'}<div class="report-links"><a href="https://www.abuseipdb.com/check/${encodeURIComponent(result.ipAddress)}" target="_blank" rel="noopener">Open AbuseIPDB report</a>${result.vtEnabled ? `<a href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(result.ipAddress)}/detection" target="_blank" rel="noopener">Open VirusTotal report</a>` : ''}</div>`;
  $('reportDialog').hidden = false;
}
async function checkTarget(target, source, targetType) {
  target = normalizeTarget(target);
  if (isHost(target)) {
    const response = await fetch(`/api/resolve?host=${encodeURIComponent(target)}`, { headers: { Accept: 'application/json' } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || (response.status === 404 ? 'The running server needs to be restarted to enable hostname resolution.' : `Hostname resolution failed (${response.status})`));
    return Promise.all(data.addresses.map(address => checkIP(address, source, targetType)));
  }
  if (!isURL(target)) return [await checkIP(target, source, targetType)];
  const response = await fetch(`/api/resolve?url=${encodeURIComponent(target)}`, { headers: { Accept: 'application/json' } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || (response.status === 404 ? 'The running server needs to be restarted to enable URL resolution.' : `URL resolution failed (${response.status})`));
  return Promise.all(data.addresses.map(address => checkIP(address, source, targetType, targetType === 'url' ? target : '')));
// made with AI
// directed by
// Jahid Hossain Sabit
}
async function runChecks() {
  const entries = getIPs($('ipInput').value); const valid = []; const invalid = [];
  entries.forEach(entry => { try { const expanded = expandInput(entry); const source = displayTarget(entry); if (!expanded) invalid.push({ source, ipAddress: entry, error: 'Enter an IP, CIDR range, or HTTP(S) URL' }); else valid.push(...expanded.map(value => ({ value, source }))); } catch (error) { invalid.push({ source: displayTarget(entry), ipAddress: entry, error: error.message }); } });
  if (!entries.length) return showToast('Add at least one IP, CIDR range, or URL.');
  const uniqueValid = [...new Map(valid.map(item => [`${item.source}|${item.value}`, item])).values()];
  state.results = invalid;
  $('checkButton').disabled = true; $('checkButton').textContent = 'Checking…'; $('progressBar').style.width = '0%'; $('progressText').textContent = `Preparing ${uniqueValid.length} target${uniqueValid.length === 1 ? '' : 's'}…`; showView('loadingView');
  if (!uniqueValid.length) $('progressText').textContent = 'No valid targets to check.';
  for (let i = 0; i < uniqueValid.length; i++) { const item = uniqueValid[i]; try { const targetType = isURL(item.value) ? 'url' : item.source.includes('/') ? 'cidr' : 'ip'; state.results.push(...await checkTarget(item.value, item.source, targetType)); } catch (error) { state.results.push({ source: item.source, ipAddress: item.value, error: error.message }); } $('progressBar').style.width = `${((i + 1) / uniqueValid.length) * 100}%`; $('progressText').textContent = `Checking ${i + 1} of ${uniqueValid.length}`; }
  $('checkButton').disabled = false; $('checkButton').innerHTML = 'Check reputation <span>→</span>'; $('progressText').textContent = 'Complete'; renderResults(); showView('resultsView');
}
function download(filename, content, type) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = filename; a.click(); URL.revokeObjectURL(a.href); }
function exportCSV() { if (!state.results.length) return showToast('There are no results to export.'); const header = ['source','ipAddress','country','usageType','isp','abuseIsp','vtIsp','domain','abuseConfidenceScore','abuseWeight','vtMalicious','vtMaliciousWeight','vtSuspicious','vtSuspiciousWeight','totalWeight','finalVerdict','note','virusTotalError']; const lines = state.results.map(r => header.map(k => `"${String(r[k] ?? r.error ?? '').replaceAll('"','""')}"`).join(',')); download('ip-reputation-results.csv', [header.join(','), ...lines].join('\n'), 'text/csv'); }
function emailEligibleResults() { return state.results.filter(r => !r.error && (state.emailMode === 'all' || ((r.finalVerdict === 'MAL' || r.finalVerdict === 'SUSP') && !isTrustedResult(r)))); }
function emailPreview() { const source = escapeHTML($('sourceInput').value || '[source]'); const activity = escapeHTML($('activityInput').value || '[activity]'); const name = escapeHTML($('nameInput').value || '[name]'); const email = escapeHTML($('emailInput').value || '[email]'); const good = emailEligibleResults(); $('emailPreview').innerHTML = `<p>Dear Respective,</p><p>The following was detected by our <strong>${source}</strong> as <strong>${activity}</strong>.</p><div class="table-wrap"><table><thead><tr><th>IP Address</th><th>Country</th><th>Usage Type</th><th>ISP</th><th>Domain</th><th>Destination</th></tr></thead><tbody>${good.map((r,i) => `<tr><td>${escapeHTML(r.ipAddress)}</td><td>${escapeHTML(r.country || '—')}</td><td>${escapeHTML(r.usageType || '—')}</td><td>${escapeHTML(r.isp || '—')}</td><td>${escapeHTML(r.domain || '—')}</td><td><input class="destination-input" data-destination="${i}" value="${escapeHTML(state.destinations[i] || '')}" placeholder="Enter destination" /></td></tr>`).join('')}</tbody></table></div><p>Regards,<br />${name}<br />${email}</p>`; }
function copyEmail() {
  const good = emailEligibleResults();
  const source = escapeHTML($('sourceInput').value || '[source]');
  const activity = escapeHTML($('activityInput').value || '[activity]');
  const name = escapeHTML($('nameInput').value || '[name]');
  const email = escapeHTML($('emailInput').value || '[email]');
  const headers = ['IP Address', 'Country', 'Usage Type', 'ISP', 'Domain', 'Destination'];
  const values = good.map((r, i) => [r.ipAddress, r.country || '—', r.usageType || '—', r.isp || '—', r.domain || '—', state.destinations[i] || '']);
  const text = `Dear Respective,\n\nThe following was detected by our ${$('sourceInput').value || '[source]'} as ${$('activityInput').value || '[activity]'}.\n\n${headers.join('\t')}\n${values.map(row => row.join('\t')).join('\n')}\n\nRegards,\n${$('nameInput').value || '[name]'}\n${$('emailInput').value || '[email]'}`;
  const html = `<div style="font-family:'IDLC',Arial,sans-serif;font-size:11pt;color:#000"><p>Dear Respective,</p><p>The following was detected by our <strong>${source}</strong> as <strong>${activity}</strong>.</p><table style="border-collapse:collapse;border:1px solid #111;font-family:'IDLC',Arial,sans-serif;font-size:10pt"><thead><tr>${headers.map(h => `<th style="border:1px solid #111;background:#c90000;color:#fff;padding:7px 9px;text-align:left;white-space:nowrap">${h}</th>`).join('')}</tr></thead><tbody>${values.map(row => `<tr>${row.map(value => `<td style="border:1px solid #111;padding:7px 9px;vertical-align:top">${escapeHTML(value)}</td>`).join('')}</tr>`).join('')}</tbody></table><p>Regards,<br>${name}<br>${email}</p></div>`;
  if (navigator.clipboard?.write && window.ClipboardItem) {
    const clipboardItem = new ClipboardItem({ 'text/html': new Blob([html], { type: 'text/html' }), 'text/plain': new Blob([text], { type: 'text/plain' }) });
    navigator.clipboard.write([clipboardItem]).then(() => showToast('Formatted email table copied.')).catch(() => navigator.clipboard.writeText(text).then(() => showToast('Plain-text email copied.')));
  } else {
    navigator.clipboard.writeText(text).then(() => showToast('Plain-text email copied.')).catch(() => showToast('Copy failed. Select the text manually.'));
  }
}
$('checkButton').addEventListener('click', runChecks);
$('noProxy').addEventListener('change', toggleProxyFields);
$('useProxy').addEventListener('change', toggleProxyFields);
$('saveProxyButton').addEventListener('click', saveProxySettings);
$('clearInput').addEventListener('click', () => { $('ipInput').value = ''; });
$('fileInput').addEventListener('change', async e => { const file = e.target.files[0]; if (!file) return; const text = await file.text(); const lines = file.name.toLowerCase().endsWith('.csv') ? text.split(/\r?\n/).slice(/ip_?address/i.test(text.split(/\r?\n/)[0]) ? 1 : 0).map(line => line.split(',')[0]) : [text]; $('ipInput').value = [$('ipInput').value, ...lines].filter(Boolean).join('\n'); showToast(`${file.name} added.`); e.target.value = ''; });
$('templateButton').addEventListener('click', () => download('ip-checker-template.csv', 'ip_address\n192.168.1.1\n2001:db8::1\n', 'text/csv'));
$('exportButton').addEventListener('click', exportCSV);
$('emailButton').addEventListener('click', () => openEmail('flagged'));
$('allEmailButton').addEventListener('click', () => openEmail('all'));
function openEmail(mode) { state.emailMode = mode; if (!emailEligibleResults().length) return showToast(mode === 'all' ? 'There are no valid IPs to include in the email.' : 'There are no suspicious or malicious IPs to include in the email.'); showView('emailView'); emailPreview(); }
$('backButton').addEventListener('click', () => showView('resultsView'));
$('backToResultsButton').addEventListener('click', () => showView('checkerView'));
$('backToProxyButton').addEventListener('click', () => { $('checkerView').hidden = true; $('proxyView').hidden = false; });
$('connectivityButton').addEventListener('click', () => showView('connectivityView'));
$('backToCheckerButton').addEventListener('click', () => showView('proxyView'));
function resetConnectivityFlow() {
  const flow = $('connectivityFlow');
  flow.className = 'connectivity-flow is-running';
  flow.querySelectorAll('[data-flow-node], [data-flow-line]').forEach(element => element.classList.remove('is-ok', 'is-error', 'is-active'));
  flow.querySelector('[data-flow-node="pc"]').classList.add('is-ok');
  flow.querySelector('[data-flow-node="internet"]').classList.add('is-active');
  flow.querySelector('[data-flow-line="internet"]').classList.add('is-active');
}
function updateConnectivityFlow(checks) {
  const flow = $('connectivityFlow');
  const setState = (selector, result) => { const element = flow.querySelector(selector); if (!element) return; element.classList.remove('is-ok', 'is-error', 'is-active'); if (result) element.classList.add(result.ok ? 'is-ok' : 'is-error'); };
  setState('[data-flow-node="internet"]', checks.internet);
  setState('[data-flow-line="internet"]', checks.internet);
  setState('[data-flow-node="abuseipdb"]', checks.abuseipdb);
  setState('[data-flow-line="abuseipdb"]', checks.abuseipdb);
  setState('[data-flow-node="virustotal"]', checks.virustotal);
  setState('[data-flow-line="virustotal"]', checks.virustotal);
  const allPassed = Object.keys(checks).length === 3 && Object.values(checks).every(result => result.ok);
  const complete = flow.querySelector('[data-flow-node="complete"]');
  const completeLine = flow.querySelector('[data-flow-line="complete"]');
  complete.classList.remove('is-ok', 'is-error', 'is-active');
  completeLine.classList.remove('is-ok', 'is-error', 'is-active');
  const completeState = allPassed ? 'is-ok' : Object.keys(checks).length === 3 ? 'is-error' : '';
  if (completeState) { complete.classList.add(completeState); completeLine.classList.add(completeState); }
  flow.classList.toggle('is-complete', allPassed);
  flow.classList.toggle('is-error', Object.values(checks).some(result => !result.ok));
}
function activateConnectivityBranch(key) {
  const flow = $('connectivityFlow');
  flow.querySelector(`[data-flow-node="${key}"]`)?.classList.add('is-active');
  flow.querySelector(`[data-flow-line="${key}"]`)?.classList.add('is-active');
}
function wait(milliseconds) { return new Promise(resolve => setTimeout(resolve, milliseconds)); }
async function runConnectivityCheck() {
  const button = $('runConnectivityButton');
  button.disabled = true;
  button.textContent = 'Testing…';
  resetConnectivityFlow();
  $('connectivityContinueButton').hidden = true;
  $('configureProxyButton').hidden = true;
  try {
    const response = await fetch('/api/connectivity', { headers: { Accept: 'application/json' } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.errors?.[0]?.detail || 'Connectivity test failed.');
    const displayedChecks = {};
    for (const key of ['internet', 'abuseipdb', 'virustotal']) {
      activateConnectivityBranch(key);
      await wait(650);
// made with AI
// directed by
// Jahid Hossain Sabit
      const result = data.checks[key];
      displayedChecks[key] = result;
      updateConnectivityFlow(displayedChecks);
    }
    await wait(450);
    const allPassed = Object.values(displayedChecks).every(result => result.ok);
    $('connectivityContinueButton').hidden = !allPassed;
    $('configureProxyButton').hidden = allPassed;
    showView('connectivityView');
  } catch (error) {
    $('connectivityFlow').classList.add('is-error');
    $('connectivityFlow').querySelector('[data-flow-node="complete"]').classList.add('is-error');
    $('connectivityContinueButton').hidden = true;
    $('configureProxyButton').hidden = false;
    showView('connectivityView');
  } finally {
    button.disabled = false;
    button.innerHTML = 'Run connectivity test <span>→</span>';
  }
}
$('runConnectivityButton').addEventListener('click', runConnectivityCheck);
$('connectivityContinueButton').addEventListener('click', () => showView('checkerView'));
$('configureProxyButton').addEventListener('click', () => showView('proxyView'));
$('themeToggle').addEventListener('click', toggleTheme);
updateThemeToggle();
['sourceInput','activityInput','nameInput','emailInput'].forEach(id => $(id).addEventListener('input', emailPreview));
$('emailPreview').addEventListener('input', e => { if (e.target.matches('[data-destination]')) state.destinations[e.target.dataset.destination] = e.target.value; });
$('copyEmailButton').addEventListener('click', copyEmail);
$('resultsTable').addEventListener('click', event => { const button = event.target.closest('[data-sort-key]'); if (button) sortResults(button.dataset.sortKey); });
$('resultsBody').addEventListener('click', event => { const button = event.target.closest('[data-report]'); if (button) openReport(state.results[Number(button.dataset.report)]); });
$('closeReportButton').addEventListener('click', () => { $('reportDialog').hidden = true; });
$('reportDialog').addEventListener('click', event => { if (event.target === $('reportDialog')) $('reportDialog').hidden = true; });
