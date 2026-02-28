/**
 * =====================================================================
 *  VULNERABLE SERVER — Prototype Pollution POC
 *  WARNING: This server is intentionally vulnerable for educational purposes.
 *           DO NOT deploy this in production.
 * =====================================================================
 *
 *  Vulnerabilities demonstrated:
 *    1. Privilege Escalation via unsafe deep merge
 *    2. DoS via property type confusion
 *    3. RCE via polluted template rendering options
 *
 *  Run: node src/server-vulnerable.js
 *  Port: 3000
 */

const express = require('express');
const app = express();
app.use(express.json());

// -------------------------------------------------------
// Unsafe recursive merge (simulates vulnerable libraries
// like merge@1.2.1, lodash < 4.17.21, defaults-deep, etc.)
// -------------------------------------------------------
function unsafeMerge(target, source) {
  for (const key in source) {
    // BUG: does NOT skip __proto__ or constructor
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// -------------------------------------------------------
// In-memory "database" of users
// -------------------------------------------------------
const users = {
  alice: { username: 'alice', password: 'alice123', role: 'user' },
  bob:   { username: 'bob',   password: 'bob123',   role: 'user' },
};

// -------------------------------------------------------
// Simple template renderer (simulates pug/jade behavior)
// Used to demonstrate RCE potential
// -------------------------------------------------------
function renderTemplate(templateName, options) {
  // In real pug, options.outputFunctionName reaches eval()
  // We simulate this danger safely by just logging it
  console.log(`[TEMPLATE] Rendering: ${templateName}`);
  console.log(`[TEMPLATE] Options received:`, JSON.stringify(options));

  // DANGEROUS: if options.dangerousOption was injected via prototype pollution,
  // a real template engine would pass it to eval/Function() here.
  if (options.dangerousOption) {
    console.log(`[RCE SIMULATION] Would execute: ${options.dangerousOption}`);
    return `<html><body><h1>RCE Triggered! Command: ${options.dangerousOption}</h1></body></html>`;
  }
  return `<html><body><h1>Welcome to ${templateName}</h1></body></html>`;
}

// -------------------------------------------------------
// ROUTE 1: /api/update-profile
// Unsafe merge of user input into user profile object
// → Exploitable for Privilege Escalation
// -------------------------------------------------------
app.post('/api/update-profile', (req, res) => {
  const { username, updates } = req.body;

  if (!username || !users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }

  console.log(`[UPDATE] Merging updates for user: ${username}`);
  console.log(`[UPDATE] Payload:`, JSON.stringify(updates));

  // VULNERABILITY: unsafeMerge will follow __proto__ key
  unsafeMerge(users[username], updates);

  res.json({ message: 'Profile updated', user: users[username] });
});

// -------------------------------------------------------
// ROUTE 2: /api/admin
// Checks if user is admin — exploitable via polluted prototype
// -------------------------------------------------------
app.get('/api/admin', (req, res) => {
  const user = {}; // fresh empty object — no role set
  console.log(`[ADMIN CHECK] user.isAdmin = ${user.isAdmin}`);
  console.log(`[ADMIN CHECK] user.role    = ${user.role}`);

  if (user.isAdmin || user.role === 'admin') {
    return res.json({
      access: 'GRANTED',
      message: '🔓 Welcome, Admin! You have full system access.',
      secretData: 'FLAG{pr0t0type_p0lluti0n_pwned_y0u}'
    });
  }

  res.status(403).json({
    access: 'DENIED',
    message: '🔒 You are not an admin.'
  });
});

// -------------------------------------------------------
// ROUTE 3: /api/settings
// Returns JSON.parse of user input — DoS vector
// -------------------------------------------------------
app.post('/api/settings', (req, res) => {
  const defaults = { timeout: 30, retries: 3, debug: false };

  console.log(`[SETTINGS] Merging settings...`);
  // VULNERABILITY: if Object.prototype.timeout was set to a string,
  // code depending on typeof timeout === 'number' will break
  unsafeMerge(defaults, req.body);

  const timeout = defaults.timeout;
  console.log(`[SETTINGS] Timeout value: ${timeout} (type: ${typeof timeout})`);

  // Simulate server logic that uses timeout as a number
  try {
    const result = timeout * 1000; // Will produce NaN if polluted with string
    if (isNaN(result)) throw new Error('Invalid timeout — server configuration corrupted!');
    res.json({ message: 'Settings applied', timeout: result });
  } catch (err) {
    // DoS: server returns 500 for every subsequent request
    console.error(`[DOS] Server config corrupted: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------
// ROUTE 4: /api/render
// Passes options to template engine — RCE vector
// -------------------------------------------------------
app.post('/api/render', (req, res) => {
  const { template, options } = req.body;

  // Merge user options into default render options
  const renderOptions = {};
  unsafeMerge(renderOptions, options || {});

  console.log(`[RENDER] Rendering template with options:`, renderOptions);

  // VULNERABILITY: if __proto__.dangerousOption was set earlier,
  // renderOptions (empty {}) will inherit it via prototype chain
  const html = renderTemplate(template || 'index', renderOptions);
  res.send(html);
});

// -------------------------------------------------------
// Health check / status
// -------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    server: 'Prototype Pollution — Vulnerable Demo Server',
    status: 'running',
    routes: [
      'POST /api/update-profile  → Privilege escalation vector',
      'GET  /api/admin           → Authorization check',
      'POST /api/settings        → DoS vector',
      'POST /api/render          → RCE simulation vector',
    ]
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   ⚠️  VULNERABLE SERVER RUNNING — EDUCATIONAL ONLY  ║');
  console.log(`║   Listening on http://localhost:${PORT}                ║`);
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
});
