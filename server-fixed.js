/**
 * =====================================================================
 *  SECURE SERVER — Prototype Pollution POC (Patched Version)
 *  Demonstrates all defenses against Prototype Pollution
 *
 *  Run: node fixes/server-fixed.js
 *  Port: 3001
 * =====================================================================
 *
 *  Defenses applied:
 *    1. DEFENSE 1 — Key sanitization: block __proto__, constructor, prototype
 *    2. DEFENSE 2 — Object.keys() instead of for...in (no prototype traversal)
 *    3. DEFENSE 3 — Object.freeze(Object.prototype) at startup
 *    4. DEFENSE 4 — Object.create(null) for data storage
 *    5. DEFENSE 5 — Input schema validation before any merge
 */

const express = require('express');
const app = express();

// DEFENSE: Custom body parser that checks raw bytes for dangerous keys
app.use((req, res, next) => {
  if (req.is('application/json')) {
    let rawBody = '';
    let hasDangerousKey = false;
    req.setEncoding('utf8');
    req.on('data', chunk => {
      rawBody += chunk;
      // Check as we read to detect "__proto__", "constructor", "prototype" with quotes
      if (!hasDangerousKey && /"__proto__"|"constructor"|"prototype"/.test(chunk)) {
        console.warn(`[SECURITY] Detected dangerous key in streaming JSON request: ${chunk.substring(0, 100)}`);
        hasDangerousKey = true;
      }
    });
    req.on('end', () => {
      console.log(`[DEBUG middleware] Raw body: ${rawBody.substring(0, 150)}`);
      if (hasDangerousKey) {
        console.log('[DEBUG middleware] Rejecting due to dangerous key');
        return res.status(400).json({error: 'Invalid input', details: ['Forbidden key: "__proto__", "constructor", or "prototype" detected']});
      }
      try {
        req.body = JSON.parse(rawBody);
        next();
      } catch (e) {
        res.status(400).json({error: 'Invalid JSON'});
      }
    });
  } else {
    express.json()(req, res, next);
  }
});

// -------------------------------------------------------
// DEFENSE 3: Freeze Object.prototype at startup
// Any attempt to set properties on it will throw TypeError
// -------------------------------------------------------
Object.freeze(Object.prototype);
console.log('[SECURITY] Object.prototype is now frozen.');

// -------------------------------------------------------
// DEFENSE 1 + 2: Safe recursive merge
//   - Uses Object.keys() → does NOT traverse prototype chain
//   - Explicitly blocks dangerous keys
// -------------------------------------------------------

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Recursively check for dangerous keys at any depth
function containsDangerousKey(obj) {
  if (typeof obj !== 'object' || obj === null) return false;
  
  // Check both enumerable (Object.keys) and non-enumerable (Object.getOwnPropertyNames) properties
  const allKeys = Object.getOwnPropertyNames(obj);
  for (const key of allKeys) {
    console.log(`[DEBUG containsDangerousKey] Checking key: "${key}", DANGEROUS_KEYS has it: ${DANGEROUS_KEYS.has(key)}`);
    if (DANGEROUS_KEYS.has(key)) return true;
    if (typeof obj[key] === 'object' && containsDangerousKey(obj[key])) return true;
  }
  return false;
}

function safeMerge(target, source) {
  // Object.keys() only returns own enumerable properties — never __proto__
  for (const key of Object.keys(source)) {
    // DEFENSE 1: Deny-list dangerous keys
    if (DANGEROUS_KEYS.has(key)) {
      console.warn(`[SECURITY] Blocked dangerous key: "${key}"`);
      continue;
    }

    if (
      typeof source[key] === 'object' &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      // DEFENSE 4: Use Object.create(null) for nested objects
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = Object.create(null);
      }
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// -------------------------------------------------------
// DEFENSE 5: Input schema validator
// Only allows known, expected keys through
// -------------------------------------------------------
function validateProfileUpdates(updates) {
  const ALLOWED_KEYS = new Set(['displayName', 'email', 'bio', 'avatar']);
  const errors = [];

  console.log(`[DEBUG validateProfileUpdates] updates keys: ${JSON.stringify(Object.keys(updates || {}))}`);
  console.log(`[DEBUG validateProfileUpdates] updates: ${JSON.stringify(updates)}`);
  
  // Check if the updates object itself has been polluted (prototype has been modified)
  if (updates && Object.getPrototypeOf(updates) !== Object.prototype) {
    errors.push('Forbidden key: "__proto__" attack detected - prototype has been modified');
    console.log('[DEBUG validateProfileUpdates] Prototype pollution detected!');
    return errors;
  }

  if (containsDangerousKey(updates)) {
    errors.push('Forbidden key: "__proto__", "constructor", or "prototype" detected');
    console.log('[DEBUG validateProfileUpdates] Dangerous key found!');
    return errors;
  }

  for (const key of Object.keys(updates || {})) {
    if (!ALLOWED_KEYS.has(key)) {
      errors.push(`Unknown key: "${key}" — only allowed: ${[...ALLOWED_KEYS].join(', ')}`);
    }
  }

  console.log(`[DEBUG validateProfileUpdates] errors: ${JSON.stringify(errors)}`);
  return errors;
}

function validateSettings(settings) {
  const errors = [];

  console.log(`[DEBUG validateSettings] settings keys: ${JSON.stringify(Object.keys(settings || {}))}`);
  console.log(`[DEBUG validateSettings] settings all properties: ${JSON.stringify(Object.getOwnPropertyNames(settings || {}))}`);

  // Check if the settings object itself has been polluted (prototype has been modified)
  if (settings && Object.getPrototypeOf(settings) !== Object.prototype) {
    errors.push('Forbidden key: "__proto__" attack detected - prototype has been modified');
    console.log('[DEBUG validateSettings] Prototype pollution detected!');
    return errors;
  }

  if (containsDangerousKey(settings)) {
    errors.push('Forbidden key: "__proto__", "constructor", or "prototype" detected');
    return errors;
  }

  if (settings.timeout !== undefined && typeof settings.timeout !== 'number') {
    errors.push(`"timeout" must be a number, got: ${typeof settings.timeout}`);
  }
  if (settings.retries !== undefined && typeof settings.retries !== 'number') {
    errors.push(`"retries" must be a number, got: ${typeof settings.retries}`);
  }
  return errors;
}

// -------------------------------------------------------
// DEFENSE 4: In-memory DB using Object.create(null)
// These objects have NO prototype — cannot be polluted
// -------------------------------------------------------
const users = Object.create(null);
users.alice = Object.assign(Object.create(null), { username: 'alice', role: 'user' });
users.bob   = Object.assign(Object.create(null), { username: 'bob',   role: 'user' });

// -------------------------------------------------------
// Safe template renderer — does not use dynamic options
// -------------------------------------------------------
function safeRenderTemplate(templateName) {
  return `<html><body><h1>Secure page: ${templateName}</h1></body></html>`;
}

// -------------------------------------------------------
// ROUTE 1: /api/update-profile (PATCHED)
// -------------------------------------------------------
app.post('/api/update-profile', (req, res) => {
  const { username, updates } = req.body;

  if (!username || !users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }

  console.log('[DEBUG] updates received:', Object.keys(updates || {}));

  // DEFENSE 5: Validate input before merging
  const errors = validateProfileUpdates(updates);
  if (errors.length > 0) {
    console.warn('[SECURITY] Rejected invalid input:', errors);
    return res.status(400).json({ error: 'Invalid input', details: errors });
  }

  // DEFENSE 1+2: Use safeMerge instead of unsafeMerge
  safeMerge(users[username], updates);

  res.json({ message: 'Profile updated securely', user: { ...users[username] } });
});

// -------------------------------------------------------
// ROUTE 2: /api/admin (PATCHED)
// -------------------------------------------------------
app.get('/api/admin', (req, res) => {
  // DEFENSE 4: Use Object.create(null) — no prototype, no inherited isAdmin
  const user = Object.create(null);
  console.log(`[ADMIN CHECK] user.isAdmin = ${user.isAdmin}`); // always undefined

  // Also use hasOwnProperty to be extra safe
  const hasAdminRole = Object.prototype.hasOwnProperty.call(user, 'role') &&
                       user.role === 'admin';

  if (hasAdminRole) {
    return res.json({ access: 'GRANTED', message: 'Welcome, Admin!' });
  }

  res.status(403).json({ access: 'DENIED', message: 'You are not an admin.' });
});

// -------------------------------------------------------
// ROUTE 3: /api/settings (PATCHED)
// -------------------------------------------------------
app.post('/api/settings', (req, res) => {
  // DEFENSE 5: Validate types before merge
  const errors = validateSettings(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: 'Invalid settings', details: errors });
  }

  // DEFENSE 4: Start from null-prototype object
  const defaults = Object.assign(Object.create(null), { timeout: 30, retries: 3, debug: false });

  // DEFENSE 1+2: Safe merge
  safeMerge(defaults, req.body);

  const timeout = defaults.timeout;
  const result = timeout * 1000; // Safe — timeout is guaranteed to be a number

  res.json({ message: 'Settings applied securely', timeout: result });
});

// -------------------------------------------------------
// ROUTE 4: /api/render (PATCHED)
// -------------------------------------------------------
app.post('/api/render', (req, res) => {
  const { template } = req.body;
  // DEFENSE: Do NOT pass any user-controlled object to template renderer
  const html = safeRenderTemplate(template || 'index');
  res.send(html);
});

// -------------------------------------------------------
// Health check
// -------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    server: 'Prototype Pollution — SECURE Demo Server',
    status: 'running',
    defenses: [
      'Object.prototype is frozen',
      'safeMerge() blocks __proto__, constructor, prototype keys',
      'Object.keys() used instead of for...in',
      'Object.create(null) used for all data objects',
      'Input schema validation before merge',
    ]
  });
});

const PORT = 3002;
app.listen(PORT, (err) => {
  if (err) {
    console.error('❌ Failed to start the server:', err);
    process.exit(1);
  }
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   ✅  SECURE SERVER RUNNING                          ║');
  console.log(`║   Listening on http://localhost:${PORT}                ║`);
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
});
