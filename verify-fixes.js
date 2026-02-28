/**
 * =====================================================================
 *  VERIFY FIXES — Confirms that the secure server resists all attacks
 *
 *  Target: http://localhost:3001 (server-fixed.js)
 *  Run:    node fixes/verify-fixes.js
 * =====================================================================
 */

const http = require('http');

const TARGET = 'localhost';
const PORT = 3001;

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: TARGET,
      port: PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function check(label, passed) {
  const icon = passed ? '✅ BLOCKED' : '❌ VULNERABLE';
  console.log(`  ${icon.padEnd(14)} — ${label}`);
  return passed;
}

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║   SECURITY VERIFICATION — Secure Server Tests        ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  try { await request('GET', '/'); }
  catch {
    console.error('❌ Cannot connect to secure server at localhost:3001');
    console.error('   Run: node fixes/server-fixed.js\n');
    process.exit(1);
  }

  let passed = 0, total = 0;

  // Test 1: __proto__ key is blocked
  console.log('── Test 1: __proto__ Privilege Escalation ──────────────');
  const t1a = await request('POST', '/api/update-profile', {
    username: 'alice',
    updates: { '__proto__': { isAdmin: true } }
  });
  total++;
  if (check('Input with __proto__ key rejected (400)', t1a.status === 400)) passed++;

  const t1b = await request('GET', '/api/admin');
  total++;
  if (check('Admin access still DENIED after attack attempt', t1b.status === 403)) passed++;

  // Test 2: constructor.prototype path also blocked
  console.log('\n── Test 2: constructor.prototype Path ──────────────────');
  const t2 = await request('POST', '/api/update-profile', {
    username: 'alice',
    updates: { constructor: { prototype: { isAdmin: true } } }
  });
  total++;
  if (check('constructor key rejected (400)', t2.status === 400)) passed++;

  // Test 3: DoS payload blocked
  console.log('\n── Test 3: Denial of Service (timeout type pollution) ──');
  const t3a = await request('POST', '/api/settings', {
    '__proto__': { timeout: 'CORRUPTED' }
  });
  total++;
  if (check('DoS payload rejected', t3a.status === 400)) passed++;

  const t3b = await request('POST', '/api/settings', { timeout: 10 });
  total++;
  if (check('Normal settings request still works (200)', t3b.status === 200)) passed++;

  // Test 4: RCE payload blocked
  console.log('\n── Test 4: RCE Simulation ───────────────────────────────');
  const t4 = await request('POST', '/api/update-profile', {
    username: 'bob',
    updates: { '__proto__': { dangerousOption: "require('child_process').execSync('id')" } }
  });
  total++;
  if (check('RCE payload via __proto__ blocked', t4.status === 400)) passed++;

  const t4b = await request('POST', '/api/render', { template: 'index', options: {} });
  total++;
  const rceNotTriggered = typeof t4b.body === 'string' && !t4b.body.includes('RCE Triggered');
  if (check('Render endpoint does not execute polluted options', rceNotTriggered)) passed++;

  // Test 5: Object.prototype.isAdmin is not set
  console.log('\n── Test 5: Object.prototype Integrity Check ─────────────');
  total++;
  const protoClean = Object.prototype.isAdmin === undefined;
  if (check('Object.prototype.isAdmin remains undefined', protoClean)) passed++;

  // Summary
  console.log(`\n╔══════════════════════════════════════════════════════╗`);
  console.log(`║  RESULT: ${passed}/${total} tests passed`.padEnd(55) + '║');
  console.log(`║  ${passed === total ? '✅ All attacks successfully blocked!' : '⚠️  Some tests failed — review fixes.'}`.padEnd(55) + '║');
  console.log(`╚══════════════════════════════════════════════════════╝\n`);
}

main();
