import crypto from 'node:crypto';

const MAILTM_BASE = 'https://api.mail.tm';
const ALGORITHM = 'aes-256-gcm';

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
 * Fetch available active domains from official Mail.tm API:
 * GET https://api.mail.tm/domains
 */
async function getAvailableDomains() {
  const now = Date.now();
  if (cachedDomains.length > 0 && (now - lastDomainsFetch < 10 * 60 * 1000)) {
    return cachedDomains;
  }

  try {
    const res = await fetch(`${MAILTM_BASE}/domains`);
    if (!res.ok) {
      throw new Error(`Mail.tm /domains returned HTTP ${res.status}`);
    }
    const data = await res.json();
    const members = data['hydra:member'] || [];
    const active = members.filter(d => d.isActive !== false).map(d => d.domain.toLowerCase());

    if (active.length > 0) {
      cachedDomains = active;
      lastDomainsFetch = now;
      return cachedDomains;
    }
  } catch (err) {
    console.error('Error fetching domains from Mail.tm:', err.message);
  }

  return cachedDomains.length > 0 ? cachedDomains : ['maxxspace.com'];
}

async function getActiveDomain() {
  const domains = await getAvailableDomains();
  return domains[0];
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
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ address, password })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Mail.tm /token failed (${res.status}): ${errText}`);
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
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ address, password })
  });

  if (!res.ok) {
    const errBody = await res.text();
    const error = new Error(`Mail.tm /accounts failed (${res.status}): ${errBody}`);
    error.status = res.status;
    error.details = errBody;
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
 * Main API Handler (Serverless & Node HTTP Server compatible)
 */
export default async function handler(req, res) {
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

      // Step 1: Fetch available Mail.tm domain
      const domain = await getActiveDomain();

      // Step 2: Generate unique address & secure password
      const randSuffix = crypto.randomBytes(4).toString('hex');
      const address = `td_${randSuffix}@${domain}`.toLowerCase();
      const password = `Tmp!${crypto.randomBytes(8).toString('base64url')}9A#`;

      // Step 3: Create temporary account on Mail.tm
      let accountData;
      try {
        accountData = await createMailtmAccount(address, password);
      } catch (err) {
        if (err.status === 429) {
          return res.status(429).json({ error: 'Mail.tm rate limit reached. Please wait a moment and try again.' });
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

      // Validate selected domain against official Mail.tm active domains
      const availableDomains = await getAvailableDomains();
      let domain = requestedDomain;
      if (!domain || !availableDomains.includes(domain)) {
        if (domain && !availableDomains.includes(domain)) {
          return res.status(400).json({ error: `Domain @${domain} is not currently supported by Mail.tm` });
        }
        domain = availableDomains[0];
      }

      const address = `${rawUser}@${domain}`;
      const password = `Tmp!${crypto.randomBytes(8).toString('base64url')}9A#`;

      let accountData;
      try {
        accountData = await createMailtmAccount(address, password);
      } catch (err) {
        if (err.status === 422) {
          return res.status(422).json({ error: 'This username is already taken. Please choose another one.' });
        }
        if (err.status === 429) {
          return res.status(429).json({ error: 'Mail.tm rate limit reached. Please wait a moment before trying again.' });
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
          'Accept': 'application/json'
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
            'Accept': 'application/json'
          }
        });
      }

      if (!msgRes.ok) {
        return res.status(msgRes.status).json({ error: 'Failed to fetch messages from Mail.tm', list: [] });
      }

      const msgData = await msgRes.json();
      const members = msgData['hydra:member'] || [];

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
          'Accept': 'application/json'
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
            'Accept': 'application/json'
          }
        });
      }

      if (!msgRes.ok) {
        return res.status(msgRes.status).json({ error: 'Failed to retrieve message details' });
      }

      const m = await msgRes.json();

      // Mark message as seen on Mail.tm via PATCH
      fetch(`${MAILTM_BASE}/messages/${emailId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/merge-patch+json'
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
          'Authorization': `Bearer ${token}`
        }
      });

      return res.status(200).json({ success: true, deleted: [emailId] });
    }

    // -------------------------------------------------------------
    // Action 6: Fetch available domains
    // -------------------------------------------------------------
    if (action === 'get_domains') {
      const domains = await getAvailableDomains();
      return res.status(200).json({
        domains: domains,
        activeDomain: domains[0]
      });
    }

    return res.status(400).json({ error: `Unsupported action: ${action}` });
  } catch (err) {
    console.error('Mail.tm proxy error:', err);
    return res.status(err.status || 500).json({
      error: err.message || 'Internal proxy error',
      details: err.details || null
    });
  }
}
