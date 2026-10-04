import crypto from 'node:crypto';
import dns from 'node:dns/promises';

const MAILTM_BASE = 'https://api.mail.tm';
const ALGORITHM = 'aes-256-gcm';
const BUILD_VERSION = '2026-10-04-v6-networkdiag';

// Common HTTP headers for Mail.tm API requests
const MAILTM_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/ld+json, application/json;q=0.9, */*;q=0.8',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
};

// Server-side session encryption key derived from environment variable
const SESSION_SECRET = process.env.SESSION_SECRET || 'tempdrop-dev-fallback-secret-key-32b';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SESSION_SECRET).digest();

// In-memory cache for warm serverless execution & local development
// sid -> { token, address, password, accountId, domain, createdAt, lastActive }
const sessions = new Map();

// Cached domains to minimize redundant network roundtrips
let cachedDomains = [];
let lastDomainsFetch = 0;

/**
 * Structured, sanitized error logger for Mail.tm API non-2xx responses.
 * Strictly redacts password and token from all log output.
 */
function logMailtmError(method, url, status, responseBody, sanitizedPayload) {
  const safePayload = sanitizedPayload ? { ...sanitizedPayload } : {};
  if (safePayload.password) safePayload.password = '[REDACTED]';
  if (safePayload.token) safePayload.token = '[REDACTED]';

  console.error('[Mail.tm API Non-2xx Response]', {
    method,
    url,
    status,
    responseBody: responseBody ? responseBody.slice(0, 1000) : '(empty body)',
    sanitizedPayload: safePayload
  });
}

/**
 * Seals session state into an authenticated, encrypted, tamper-proof token (AES-256-GCM)
 */
function sealSession(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const jsonStr = JSON.stringify(data);
  const ciphertext = Buffer.concat([cipher.update(jsonStr, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `tds_${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

/**
 * Unseals and validates an encrypted session token. Returns null if invalid or tampered with.
 */
function unsealSession(token) {
  if (!token || typeof token !== 'string' || !token.startsWith('tds_')) {
    return null;
  }
  try {
    const parts = token.slice(4).split('.');
    if (parts.length !== 3) return null;
    const [ivB64, tagB64, encB64] = parts;
    const iv = Buffer.from(ivB64, 'base64url');
    const tag = Buffer.from(tagB64, 'base64url');
    const enc = Buffer.from(encB64, 'base64url');

    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(enc), decipher.final()]);
    const session = JSON.parse(decrypted.toString('utf8'));

    if (!session || !session.address || !session.password) {
      return null;
    }
    return session;
  } catch (err) {
    return null;
  }
}

/**
 * Parses HTTP request cookies
 */
function parseCookies(req) {
  const cookieHeader = req.headers?.cookie;
  if (!cookieHeader) return {};
  const cookies = {};
  cookieHeader.split(';').forEach(c => {
    const [name, ...val] = c.trim().split('=');
    if (name) {
      cookies[name] = decodeURIComponent(val.join('='));
    }
  });
  return cookies;
}

/**
 * Sets secure HttpOnly session cookie
 */
function setSessionCookie(res, token, req) {
  const host = (req?.headers?.host || '').toLowerCase();
  const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
  const isSecure = (process.env.NODE_ENV === 'production' || process.env.VERCEL === '1') && !isLocalhost;
  const cookieFlags = [
    `tempdrop_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${24 * 60 * 60}`,
    isSecure ? 'Secure' : ''
  ].filter(Boolean).join('; ');
  res.setHeader('Set-Cookie', cookieFlags);
}

/**
 * Resolves session primarily from HttpOnly cookie (with optional param fallback)
 */
function resolveSession(req, rawSid = '') {
  // 1. Primary: HttpOnly session cookie
  const cookies = parseCookies(req);
  const cookieToken = cookies.tempdrop_session;
  if (cookieToken) {
    if (sessions.has(cookieToken)) {
      return { session: sessions.get(cookieToken), sid: cookieToken };
    }
    if (cookieToken.startsWith('tds_')) {
      const decrypted = unsealSession(cookieToken);
      if (decrypted) {
        sessions.set(cookieToken, decrypted);
        return { session: decrypted, sid: cookieToken };
      }
    }
  }

  // 2. Optional fallback: rawSid parameter (for non-browser API callers)
  if (rawSid) {
    if (sessions.has(rawSid)) {
      return { session: sessions.get(rawSid), sid: rawSid };
    }
    if (rawSid.startsWith('tds_')) {
      const decrypted = unsealSession(rawSid);
      if (decrypted) {
        sessions.set(rawSid, decrypted);
        return { session: decrypted, sid: rawSid };
      }
    }
  }

  return { session: null, sid: null };
}

/**
 * Fetch available active domains directly from official Mail.tm API:
 * GET https://api.mail.tm/domains
 * Supports forceRefresh to bypass cache when creating new accounts.
 */
async function getAvailableDomains(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedDomains.length > 0 && (now - lastDomainsFetch < 60 * 1000)) {
    return cachedDomains;
  }

  const domainsUrl = `${MAILTM_BASE}/domains`;
  let res;
  let bodyText = '';
  let contentType = '';

  try {
    res = await fetch(domainsUrl, {
      headers: {
        'Accept': 'application/ld+json, application/json;q=0.9, */*;q=0.8',
        'User-Agent': MAILTM_HEADERS['User-Agent']
      }
    });

    contentType = res.headers.get('content-type') || '(none)';
    bodyText = await res.text();

    // Required Diagnostic Logging: ONLY log requestUrl, httpStatus, contentType, bodyLength, bodyPreview
    console.log('[Mail.tm /domains Diagnostic]', {
      requestUrl: domainsUrl,
      httpStatus: res.status,
      contentType: contentType,
      bodyLength: bodyText.length,
      bodyPreview: bodyText.slice(0, 500)
    });
  } catch (netErr) {
    console.error('[Mail.tm /domains Network Error]', {
      requestUrl: domainsUrl,
      error: netErr.message
    });
    throw netErr;
  }

  if (!res.ok && res.status >= 500) {
    // Retry once after 600ms on 5xx
    try {
      await new Promise(r => setTimeout(r, 600));
      const retryRes = await fetch(domainsUrl, {
        headers: {
          'Accept': 'application/ld+json, application/json;q=0.9, */*;q=0.8',
          'User-Agent': MAILTM_HEADERS['User-Agent']
        }
      });
      const retryType = retryRes.headers.get('content-type') || '(none)';
      const retryBody = await retryRes.text();

      console.log('[Mail.tm /domains Retry Diagnostic]', {
        requestUrl: domainsUrl,
        httpStatus: retryRes.status,
        contentType: retryType,
        bodyLength: retryBody.length,
        bodyPreview: retryBody.slice(0, 500)
      });

      if (retryRes.ok) {
        res = retryRes;
        contentType = retryType;
        bodyText = retryBody;
      }
    } catch (retryErr) {
      console.error('[Mail.tm /domains Retry Network Error]', retryErr.message);
    }
  }

  if (!res.ok) {
    if (cachedDomains.length > 0) {
      console.warn(`[Mail.tm /domains HTTP ${res.status}] Fallback to cached active domains:`, cachedDomains);
      return cachedDomains;
    }
    const error = new Error(`Mail.tm /domains returned HTTP ${res.status}: ${bodyText.slice(0, 500) || '(empty body)'}`);
    error.status = res.status;
    error.details = bodyText.slice(0, 500) || '(empty body)';
    error.isMailtmError = true;
    error.diagnostic = {
      requestUrl: domainsUrl,
      httpStatus: res.status,
      contentType: contentType,
      bodyLength: bodyText.length,
      bodyPreview: bodyText.slice(0, 500)
    };
    throw error;
  }

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch (parseErr) {
    console.error('Failed to parse Mail.tm /domains response as JSON:', parseErr.message, 'Raw body preview:', bodyText.slice(0, 500));
    const error = new Error(`Failed to parse Mail.tm /domains JSON: ${parseErr.message}`);
    error.status = 502;
    error.details = bodyText.slice(0, 500);
    throw error;
  }

  // Requirement 5: Support BOTH Hydra format ({ "hydra:member": [...] }) and plain array format ([...])
  let members = [];
  if (Array.isArray(data)) {
    members = data;
  } else if (data && typeof data === 'object') {
    members = data['hydra:member'] || data.member || data.domains || [];
  }

  // Filter strictly for active, non-private domains
  const active = members
    .filter(d => d && d.domain && d.isActive !== false && d.isPrivate !== true)
    .map(d => String(d.domain).toLowerCase().trim());

  if (active.length > 0) {
    cachedDomains = active;
    lastDomainsFetch = now;
    return cachedDomains;
  }

  throw new Error('No active domains currently available from Mail.tm');
}

/**
 * Prune sessions inactive for more than 24 hours
 */
function pruneExpiredSessions() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [sid, session] of sessions.entries()) {
    if (session.lastActive < cutoff) {
      sessions.delete(sid);
    }
  }
}

/**
 * Obtain / refresh authentication token from official Mail.tm API:
 * POST https://api.mail.tm/token
 */
async function obtainAuthToken(address, password) {
  const res = await fetch(`${MAILTM_BASE}/token`, {
    method: 'POST',
    headers: MAILTM_HEADERS,
    body: JSON.stringify({ address, password })
  });

  if (!res.ok) {
    const errText = await res.text();
    const domain = address.includes('@') ? address.split('@')[1] : '';
    logMailtmError('POST', `${MAILTM_BASE}/token`, res.status, errText, {
      address,
      domain
    });
    const error = new Error(`Mail.tm /token failed (${res.status}): ${errText}`);
    error.status = res.status;
    error.details = errText;
    error.isMailtmError = true;
    throw error;
  }

  return res.json();
}

/**
 * Create a new account on official Mail.tm API:
 * POST https://api.mail.tm/accounts
 */
async function createMailtmAccount(address, password) {
  const res = await fetch(`${MAILTM_BASE}/accounts`, {
    method: 'POST',
    headers: MAILTM_HEADERS,
    body: JSON.stringify({ address, password })
  });

  if (!res.ok) {
    const errBody = await res.text();
    const domain = address.includes('@') ? address.split('@')[1] : '';
    logMailtmError('POST', `${MAILTM_BASE}/accounts`, res.status, errBody, {
      address,
      domain
    });
    const error = new Error(`Mail.tm /accounts failed (${res.status}): ${errBody || 'Internal Server Error'}`);
    error.status = res.status;
    error.details = errBody;
    error.isMailtmError = true;
    throw error;
  }

  return res.json();
}

/**
 * Ensure valid token for an existing session; re-authenticates if needed
 */
async function ensureSessionToken(session) {
  if (!session.token) {
    const authData = await obtainAuthToken(session.address, session.password);
    session.token = authData.token;
  }
  return session.token;
}

/**
 * Diagnostic probe helper for safe logging and recording without credentials.
 */
async function probeEndpoint(name, url, options = {}) {
  try {
    const res = await fetch(url, options);
    const contentType = res.headers.get('content-type') || '(none)';
    const text = await res.text();
    return {
      name,
      url,
      status: res.status,
      contentType,
      bodyLength: text.length,
      bodyPreview: text.slice(0, 500)
    };
  } catch (err) {
    return {
      name,
      url,
      status: 'NETWORK_ERROR',
      contentType: '(none)',
      bodyLength: 0,
      bodyPreview: err.message
    };
  }
}

/**
 * Main API Handler (Serverless & Node HTTP Server compatible)
 */
export default async function handler(req, res) {
  // Identify build version in response headers
  res.setHeader('X-TempDrop-Build', BUILD_VERSION);

  // CORS & credentials handling
  const origin = req.headers?.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Periodic cleanup in warm memory
  pruneExpiredSessions();

  // Parse combined parameters from query and body
  const query = req.query || {};
  const body = req.body || {};
  const params = { ...query, ...body };

  const action = params.f || params.action || '';
  const sid = params.sid_token || params.sid || '';

  try {
    // -------------------------------------------------------------
    // Diagnostic Action: Inspect /domains directly
    // -------------------------------------------------------------
    if (action === 'diagnostic' || action === 'check_domains') {
      const suiteResults = [];

      const defaultHeaders = {
        'Accept': 'application/ld+json, application/json;q=0.9, */*;q=0.8',
        'User-Agent': MAILTM_HEADERS['User-Agent']
      };

      // 1. GET https://api.mail.tm/domains
      suiteResults.push(await probeEndpoint('1. GET /domains', `${MAILTM_BASE}/domains`, {
        headers: defaultHeaders
      }));

      // 2. GET https://api.mail.tm/domains?page=1
      suiteResults.push(await probeEndpoint('2. GET /domains?page=1', `${MAILTM_BASE}/domains?page=1`, {
        headers: defaultHeaders
      }));

      // 3. GET https://api.mail.tm/
      suiteResults.push(await probeEndpoint('3. GET /', `${MAILTM_BASE}/`, {
        headers: defaultHeaders
      }));

      // 4. GET https://api.mail.tm/messages
      suiteResults.push(await probeEndpoint('4. GET /messages', `${MAILTM_BASE}/messages`, {
        headers: defaultHeaders
      }));

      // 5. POST https://api.mail.tm/accounts with valid randomly generated account
      const randSuffix = crypto.randomBytes(5).toString('hex');
      const testUsername = `diag${randSuffix}`;
      const testAddress = `${testUsername}@maxxspace.com`;
      const testPassword = `Tmp${crypto.randomBytes(8).toString('hex')}A1!`;

      suiteResults.push(await probeEndpoint('5. POST /accounts', `${MAILTM_BASE}/accounts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/ld+json, application/json;q=0.9, */*;q=0.8',
          'User-Agent': MAILTM_HEADERS['User-Agent']
        },
        body: JSON.stringify({ address: testAddress, password: testPassword })
      }));

      // Header / network variations on /domains to isolate why /domains fails
      suiteResults.push(await probeEndpoint('6. GET /domains (no custom headers)', `${MAILTM_BASE}/domains`));
      suiteResults.push(await probeEndpoint('7. GET /domains (curl User-Agent)', `${MAILTM_BASE}/domains`, {
        headers: { 'User-Agent': 'curl/8.4.0', 'Accept': '*/*' }
      }));
      suiteResults.push(await probeEndpoint('8. GET /domains (Accept: */*)', `${MAILTM_BASE}/domains`, {
        headers: { 'Accept': '*/*', 'User-Agent': MAILTM_HEADERS['User-Agent'] }
      }));
      suiteResults.push(await probeEndpoint('9. GET /domains (Accept-Encoding: identity)', `${MAILTM_BASE}/domains`, {
        headers: { ...defaultHeaders, 'Accept-Encoding': 'identity' }
      }));

      // Outbound Network & IP Diagnostics
      let outboundIp = '(unknown)';
      try {
        const ipRes = await fetch('https://api.ipify.org?format=json').then(r => r.json());
        outboundIp = ipRes.ip || '(unknown)';
      } catch (e) {
        outboundIp = `Error: ${e.message}`;
      }

      const resolvedIps4 = await dns.resolve4('api.mail.tm').catch(e => [e.message]);
      const resolvedIps6 = await dns.resolve6('api.mail.tm').catch(e => [e.message]);

      let outboundHeadersSeen = {};
      try {
        const binRes = await fetch('https://httpbin.org/headers', { headers: defaultHeaders }).then(r => r.json());
        outboundHeadersSeen = binRes.headers || {};
      } catch (e) {
        outboundHeadersSeen = { error: e.message };
      }

      console.log('[Network Diagnostic]', {
        outboundIp,
        vercelRegion: process.env.VERCEL_REGION || '(none)',
        awsRegion: process.env.AWS_REGION || '(none)',
        incomingVercelId: req.headers?.['x-vercel-id'] || '(none)',
        resolvedIps4,
        resolvedIps6
      });

      return res.status(200).json({
        build: BUILD_VERSION,
        timestamp: new Date().toISOString(),
        network: {
          outboundIp,
          vercelRegion: process.env.VERCEL_REGION || '(none)',
          awsRegion: process.env.AWS_REGION || '(none)',
          incomingVercelId: req.headers?.['x-vercel-id'] || '(none)',
          resolvedIps4,
          resolvedIps6,
          outboundHeadersSeen,
          envProxy: {
            HTTP_PROXY: process.env.HTTP_PROXY || null,
            HTTPS_PROXY: process.env.HTTPS_PROXY || null
          }
        },
        results: suiteResults
      });
    }

    // -------------------------------------------------------------
    // Action 1: Get or generate email address
    // -------------------------------------------------------------
    if (action === 'get_email_address') {
      const forceNew = params.force_new === '1' || params.force_new === 'true' || params.new === '1';

      if (!forceNew) {
        const { session, sid: activeSid } = resolveSession(req, sid);
        if (session) {
          const cutoff = 24 * 60 * 60 * 1000;
          if (Date.now() - session.createdAt < cutoff) {
            session.lastActive = Date.now();
            setSessionCookie(res, activeSid, req);
            return res.status(200).json({
              email_addr: session.address,
              mail_timestamp: Math.floor(session.createdAt / 1000)
            });
          }
        }
      }

      // Step 1: Force refresh active domains directly from GET /domains
      let availableDomains;
      try {
        availableDomains = await getAvailableDomains(true);
      } catch (err) {
        if (err.status >= 500 || err.isMailtmError) {
          return res.status(502).json({
            error: 'Mail provider temporarily unavailable. Please try again.',
            details: err.details || null,
            diagnostic: err.diagnostic || null,
            build: BUILD_VERSION
          });
        }
        throw err;
      }
      if (!availableDomains || availableDomains.length === 0) {
        return res.status(502).json({
          error: 'Mail provider has no active domains available. Please try again later.',
          build: BUILD_VERSION
        });
      }
      const domain = availableDomains[0];

      // Step 2: Generate clean alphanumeric username [a-z0-9] and secure password
      const randSuffix = crypto.randomBytes(5).toString('hex');
      const username = `td${randSuffix}`.toLowerCase();
      const address = `${username}@${domain}`;
      const password = `Tmp${crypto.randomBytes(8).toString('hex')}A1!`;

      // Step 3: Create temporary account on Mail.tm
      let accountData;
      try {
        accountData = await createMailtmAccount(address, password);
      } catch (err) {
        if (err.status === 429) {
          return res.status(429).json({ error: 'Mail provider rate limit reached. Please wait a moment and try again.' });
        }
        if (err.status >= 500) {
          return res.status(502).json({
            error: 'Mail provider temporarily unavailable. Please try again.',
            details: err.details || null,
            diagnostic: err.diagnostic || null
          });
        }
        throw err;
      }

      // Step 4: Obtain authentication token
      const tokenData = await obtainAuthToken(address, password);

      // Step 5: Seal session data into authenticated encrypted token
      const sessionData = {
        token: tokenData.token,
        address: address,
        password: password,
        accountId: accountData.id,
        domain: domain,
        createdAt: Date.now(),
        lastActive: Date.now()
      };

      const newSid = sealSession(sessionData);
      sessions.set(newSid, sessionData);
      setSessionCookie(res, newSid, req);

      return res.status(200).json({
        email_addr: address,
        mail_timestamp: Math.floor(sessionData.createdAt / 1000)
      });
    }

    // -------------------------------------------------------------
    // Action 2: Custom email address (set_email_user)
    // -------------------------------------------------------------
    if (action === 'set_email_user') {
      let rawUser = (params.email_user || params.username || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
      let requestedDomain = (params.domain || '').trim().toLowerCase().replace(/^@/, '');

      // Parse full address if provided (e.g. username@domain.com)
      if (params.address && params.address.includes('@')) {
        const parts = params.address.split('@');
        rawUser = parts[0].trim().toLowerCase().replace(/[^a-z0-9]/g, '');
        requestedDomain = parts[1].trim().toLowerCase();
      }

      if (!rawUser) {
        return res.status(400).json({ error: 'Please provide a valid alphanumeric username' });
      }

      // Validate selected domain against freshly verified active domains
      let availableDomains;
      try {
        availableDomains = await getAvailableDomains(true);
      } catch (err) {
        if (err.status >= 500 || err.isMailtmError) {
          return res.status(502).json({
            error: 'Mail provider temporarily unavailable. Please try again.',
            details: err.details || null,
            diagnostic: err.diagnostic || null,
            build: BUILD_VERSION
          });
        }
        throw err;
      }
      let domain = requestedDomain;
      if (!domain || !availableDomains.includes(domain)) {
        if (domain && !availableDomains.includes(domain)) {
          return res.status(400).json({ error: `Domain @${domain} is not currently supported or active on Mail.tm` });
        }
        domain = availableDomains[0];
      }

      const address = `${rawUser}@${domain}`;
      const password = `Tmp${crypto.randomBytes(8).toString('hex')}A1!`;

      let accountData;
      try {
        accountData = await createMailtmAccount(address, password);
      } catch (err) {
        if (err.status === 422) {
          return res.status(422).json({ error: 'This username is already taken. Please choose another one.' });
        }
        if (err.status === 429) {
          return res.status(429).json({ error: 'Mail provider rate limit reached. Please wait a moment before trying again.' });
        }
        if (err.status >= 500) {
          return res.status(502).json({
            error: 'Mail provider temporarily unavailable. Please try again.',
            details: err.details || null,
            diagnostic: err.diagnostic || null
          });
        }
        throw err;
      }

      const tokenData = await obtainAuthToken(address, password);

      const sessionData = {
        token: tokenData.token,
        address: address,
        password: password,
        accountId: accountData.id,
        domain: domain,
        createdAt: Date.now(),
        lastActive: Date.now()
      };

      const newSid = sealSession(sessionData);
      sessions.set(newSid, sessionData);
      setSessionCookie(res, newSid, req);

      return res.status(200).json({
        email_addr: address
      });
    }

    // -------------------------------------------------------------
    // Action 3: Fetch inbox messages (get_email_list)
    // -------------------------------------------------------------
    if (action === 'get_email_list') {
      const { session, sid: activeSid } = resolveSession(req, sid);
      if (!session) {
        return res.status(200).json({ list: [], count: 0 });
      }

      session.lastActive = Date.now();
      let token = await ensureSessionToken(session);

      let msgRes = await fetch(`${MAILTM_BASE}/messages?page=1`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': MAILTM_HEADERS['User-Agent']
        }
      });

      // Handle token expiration: re-login once
      if (msgRes.status === 401) {
        const authData = await obtainAuthToken(session.address, session.password);
        session.token = authData.token;
        token = authData.token;

        const refreshedSid = sealSession(session);
        sessions.set(refreshedSid, session);
        setSessionCookie(res, refreshedSid, req);

        msgRes = await fetch(`${MAILTM_BASE}/messages?page=1`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
            'User-Agent': MAILTM_HEADERS['User-Agent']
          }
        });
      }

      if (!msgRes.ok) {
        const errText = await msgRes.text();
        logMailtmError('GET', `${MAILTM_BASE}/messages?page=1`, msgRes.status, errText, {
          address: session.address,
          domain: session.domain
        });
        return res.status(msgRes.status).json({ error: 'Failed to fetch messages from Mail.tm', list: [] });
      }

      const msgData = await msgRes.json();
      // Handle both plain JSON array and hydra:member collection
      const members = Array.isArray(msgData) ? msgData : (msgData['hydra:member'] || msgData.member || []);

      // Map Mail.tm message schema to existing TempDrop UI format
      const list = members.map(m => {
        const senderName = m.from?.name?.trim();
        const senderAddr = m.from?.address || 'Unknown Sender';
        const mailFrom = senderName ? `${senderName} <${senderAddr}>` : senderAddr;
        const timestamp = Math.floor(new Date(m.createdAt).getTime() / 1000);

        return {
          mail_id: m.id,
          mail_from: mailFrom,
          mail_subject: m.subject || '(No Subject)',
          mail_excerpt: m.intro || '',
          mail_timestamp: isNaN(timestamp) ? Math.floor(Date.now() / 1000) : timestamp,
          mail_read: m.seen ? '1' : '0'
        };
      });

      return res.status(200).json({ list, count: list.length });
    }

    // -------------------------------------------------------------
    // Action 4: Fetch individual message content (fetch_email)
    // -------------------------------------------------------------
    if (action === 'fetch_email') {
      const emailId = params.email_id || params.id;
      const { session } = resolveSession(req, sid);
      if (!session || !emailId) {
        return res.status(400).json({ error: 'Session or message ID missing' });
      }

      session.lastActive = Date.now();
      let token = await ensureSessionToken(session);

      let msgRes = await fetch(`${MAILTM_BASE}/messages/${emailId}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': MAILTM_HEADERS['User-Agent']
        }
      });

      // Handle token expiration
      if (msgRes.status === 401) {
        const authData = await obtainAuthToken(session.address, session.password);
        session.token = authData.token;
        token = authData.token;

        const refreshedSid = sealSession(session);
        sessions.set(refreshedSid, session);
        setSessionCookie(res, refreshedSid, req);

        msgRes = await fetch(`${MAILTM_BASE}/messages/${emailId}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
            'User-Agent': MAILTM_HEADERS['User-Agent']
          }
        });
      }

      if (!msgRes.ok) {
        const errText = await msgRes.text();
        logMailtmError('GET', `${MAILTM_BASE}/messages/${emailId}`, msgRes.status, errText, {
          address: session.address,
          domain: session.domain
        });
        return res.status(msgRes.status).json({ error: 'Failed to retrieve message details' });
      }

      const m = await msgRes.json();

      // Mark message as seen on Mail.tm via PATCH
      fetch(`${MAILTM_BASE}/messages/${emailId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/merge-patch+json',
          'User-Agent': MAILTM_HEADERS['User-Agent']
        },
        body: JSON.stringify({ seen: true })
      }).catch(() => {});

      // Determine HTML body or plain text fallback
      const htmlBody = (Array.isArray(m.html) && m.html.length > 0 && m.html[0]) ? m.html[0] : '';
      const rawBody = htmlBody || m.text || m.intro || '';

      const senderName = m.from?.name?.trim();
      const senderAddr = m.from?.address || 'Unknown Sender';
      const mailFrom = senderName ? `${senderName} <${senderAddr}>` : senderAddr;
      const timestamp = Math.floor(new Date(m.createdAt).getTime() / 1000);

      return res.status(200).json({
        mail_id: m.id,
        mail_from: mailFrom,
        mail_subject: m.subject || '(No Subject)',
        mail_timestamp: isNaN(timestamp) ? Math.floor(Date.now() / 1000) : timestamp,
        mail_body: rawBody,
        mail_excerpt: m.intro || (m.text ? m.text.substring(0, 150) : ''),
        mail_read: '1'
      });
    }

    // -------------------------------------------------------------
    // Action 5: Delete message (del_email)
    // -------------------------------------------------------------
    if (action === 'del_email') {
      const emailId = params.email_id || params['email_ids[]'] || (Array.isArray(params.email_ids) ? params.email_ids[0] : params.email_ids);
      const { session } = resolveSession(req, sid);
      if (!session || !emailId) {
        return res.status(400).json({ error: 'Session or message ID missing for deletion' });
      }

      session.lastActive = Date.now();
      const token = await ensureSessionToken(session);

      await fetch(`${MAILTM_BASE}/messages/${emailId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'User-Agent': MAILTM_HEADERS['User-Agent']
        }
      });

      return res.status(200).json({ success: true, deleted: [emailId] });
    }

    // -------------------------------------------------------------
    // Action 6: Fetch available domains
    // -------------------------------------------------------------
    if (action === 'get_domains') {
      const domains = await getAvailableDomains(false);
      return res.status(200).json({
        domains: domains,
        activeDomain: domains[0]
      });
    }

    return res.status(400).json({ error: `Unsupported action: ${action}` });
  } catch (err) {
    console.error('Mail.tm proxy error:', err.message);
    const statusCode = err.status >= 500 || (err.message && err.message.includes('(500)')) ? 502 : (err.status || 500);
    return res.status(statusCode).json({
      error: err.status >= 500 || (err.message && err.message.includes('(500)'))
        ? 'Mail provider temporarily unavailable. Please try again.'
        : (err.message || 'Internal proxy error'),
      status: err.status || statusCode,
      details: err.details || null,
      diagnostic: err.diagnostic || null,
      build: BUILD_VERSION
    });
  }
}
