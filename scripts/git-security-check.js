#!/usr/bin/env node

/**
 * CONNECT APP BACKOFFICE – GIT SECURITY & SECRET SCANNER
 *
 * Enforces Git version control push protection for both Frontend and Backend.
 * Prevents credentials, environment files, private documents, database records,
 * backups, and private instruction files from being committed or pushed.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 1. Prohibited File Names (Exact Basenames, case-insensitive)
const PROHIBITED_BASENAMES = [
  'agent.md',
  'agents.md',
  'changelog.md'
];

// 2. Prohibited File Extensions
const PROHIBITED_EXTENSIONS = [
  '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore',
  '.dump', '.bson', '.backup', '.sqlite', '.sqlite3'
];

// 3. Prohibited Directory Patterns
const PROHIBITED_DIR_PATTERNS = [
  /(?:^|\/|\\)database-backup(?:$|\/|\\)/i,
  /(?:^|\/|\\)db-backup(?:$|\/|\\)/i,
  /(?:^|\/|\\)backups(?:$|\/|\\)/i,
  /(?:^|\/|\\)mongodb-dumps(?:$|\/|\\)/i,
  /(?:^|\/|\\)private-uploads(?:$|\/|\\)/i,
  /(?:^|\/|\\)secure-uploads(?:$|\/|\\)/i,
  /(?:^|\/|\\)customer-documents(?:$|\/|\\)/i,
  /(?:^|\/|\\)vendor-documents(?:$|\/|\\)/i,
  /(?:^|\/|\\)kyc-documents(?:$|\/|\\)/i,
  /(?:^|\/|\\)aadhaar-documents(?:$|\/|\\)/i,
  /(?:^|\/|\\)pan-documents(?:$|\/|\\)/i,
  /(?:^|\/|\\)private-storage(?:$|\/|\\)/i,
  /(?:^|\/|\\)uploads(?:\/|\\)[^.]+$/i, // runtime uploads
  /(?:^|\/|\\)test-results(?:$|\/|\\)/i,
  /(?:^|\/|\\)coverage(?:$|\/|\\)/i
];

// 4. Secret Signatures (Regex, Description)
const SECRET_SIGNATURES = [
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g
  },
  {
    name: 'MongoDB Connection String with Credentials',
    regex: /mongodb(?:\+srv)?:\/\/[^:\s"']+:[^@\s"']+@[a-zA-Z0-9.-]+/gi
  },
  {
    name: 'Redis URL with Credentials',
    regex: /rediss?:\/\/[^:\s"']*:[^@\s"']+@[a-zA-Z0-9.-]+/gi
  },
  {
    name: 'Cloudinary URL with API Secret',
    regex: /cloudinary:\/\/[0-9]+:[^@\s"']+@[a-zA-Z0-9.-]+/gi
  },
  {
    name: 'RSA/EC/OpenSSH Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g
  },
  {
    name: 'Slack Token',
    regex: /\bxox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{24,}\b/g
  }
];

// Helper to mask secret value in logs
function maskSecret(val) {
  if (!val) return '***';
  const str = String(val);
  if (str.length <= 8) return '***REDACTED***';
  return str.substring(0, 4) + '...' + str.substring(str.length - 4);
}

// Check if a path represents an environment file
function isEnvironmentFile(filePath) {
  const norm = filePath.replace(/\\/g, '/').toLowerCase();
  const base = path.basename(norm);
  if (base.endsWith('.example')) return false; // Allowed template
  if (base === '.env' || base.startsWith('.env.')) return true;
  return false;
}

// Check filename / path for prohibited patterns
function checkFilePath(filePath) {
  const norm = filePath.replace(/\\/g, '/');
  const base = path.basename(norm).toLowerCase();
  const ext = path.extname(norm).toLowerCase();

  // 1. Check prohibited instructions
  if (PROHIBITED_BASENAMES.includes(base)) {
    return {
      severity: 'CRITICAL',
      rule: 'PROHIBITED_INSTRUCTION_FILE',
      message: `Private project instruction file '${base}' must remain local and must never be committed or pushed.`
    };
  }

  // 2. Check environment files
  if (isEnvironmentFile(filePath)) {
    return {
      severity: 'CRITICAL',
      rule: 'PROHIBITED_ENV_FILE',
      message: `Environment configuration file '${filePath}' contains environment secrets and must never be committed.`
    };
  }

  // 3. Check prohibited extensions (keys, certificates, database dumps)
  if (PROHIBITED_EXTENSIONS.includes(ext)) {
    return {
      severity: 'CRITICAL',
      rule: 'PROHIBITED_EXTENSION',
      message: `Prohibited file extension '${ext}' detected in '${filePath}'. Certificates, private keys, and database dumps are not permitted.`
    };
  }

  // 4. Check prohibited directory patterns (KYC docs, private storage, database dumps)
  for (const pattern of PROHIBITED_DIR_PATTERNS) {
    if (pattern.test(norm)) {
      // Allow .gitkeep to preserve empty directory structure
      if (base === '.gitkeep') continue;
      return {
        severity: 'CRITICAL',
        rule: 'PROHIBITED_DIRECTORY',
        message: `Protected directory pattern matched for '${filePath}'. Private documents, KYC uploads, and database dumps must never be committed.`
      };
    }
  }

  return null;
}

// Check file content for secrets
function checkFileContent(filePath, content) {
  if (!content || typeof content !== 'string') return [];
  const findings = [];

  // Ignore binary / large minified files
  if (content.length > 2 * 1024 * 1024) return findings;

  for (const sig of SECRET_SIGNATURES) {
    sig.regex.lastIndex = 0;
    let match;
    while ((match = sig.regex.exec(content)) !== null) {
      const matchText = match[0];

      // Ignore safe placeholders like <api_key>, <password>, replace_with_...
      if (
        matchText.includes('<') ||
        matchText.includes('>') ||
        matchText.includes('replace_with') ||
        matchText.includes('your_') ||
        matchText.includes('dummy') ||
        matchText.includes('sample')
      ) {
        continue;
      }

      findings.push({
        severity: 'CRITICAL',
        rule: 'HARDCODED_SECRET_DETECTED',
        secretType: sig.name,
        filePath,
        masked: maskSecret(matchText)
      });
    }
  }

  // Check .env.example files for real values
  if (path.basename(filePath).toLowerCase().endsWith('.env.example')) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;
      const parts = line.split('=');
      if (parts.length > 1) {
        const val = parts.slice(1).join('=').trim();
        // Allow safe placeholder syntax (<...>, replace_with_..., empty values)
        const isPlaceholder = (
          !val ||
          val.includes('<') && val.includes('>') ||
          val.startsWith('replace_with_') ||
          val.startsWith('your_') ||
          val.startsWith('dummy') ||
          val.startsWith('sample') ||
          ['production', 'development', 'test', '8005', '3000', '5173'].includes(val) ||
          ((val.startsWith('https://') || val.startsWith('http://') || val.startsWith('wss://') || val.startsWith('ws://')) && !val.includes('@'))
        );

        if (!isPlaceholder && val.length > 15 && !val.includes(',')) {
          findings.push({
            severity: 'CRITICAL',
            rule: 'REAL_CREDENTIAL_IN_ENV_EXAMPLE',
            filePath,
            line: i + 1,
            masked: maskSecret(val),
            message: `Real credential value detected in template file '${filePath}'. .env.example must only contain safe placeholders.`
          });
        }
      }
    }
  }

  return findings;
}

// -------------------------------------------------------------
// Scan Modes
// -------------------------------------------------------------

function runPreCommit() {
  console.log('🔒 [Git Security] Executing pre-commit security verification...');
  let stagedFiles = [];
  try {
    const output = execSync('git diff --cached --name-only --diff-filter=ACM', { encoding: 'utf8' });
    stagedFiles = output.split('\n').map(s => s.trim()).filter(Boolean);
  } catch (err) {
    console.error('❌ [Git Security] Failed to query staged files:', err.message);
    process.exit(1);
  }

  if (stagedFiles.length === 0) {
    console.log('✅ [Git Security] No staged files to scan.');
    return;
  }

  const violations = [];

  for (const file of stagedFiles) {
    // 1. Path policy check
    const pathViolation = checkFilePath(file);
    if (pathViolation) {
      violations.push({ file, ...pathViolation });
      continue;
    }

    // 2. Content scan for staged content
    try {
      const stagedContent = execSync(`git show :${file}`, { encoding: 'utf8', maxBuffer: 5 * 1024 * 1024 });
      const contentViolations = checkFileContent(file, stagedContent);
      violations.push(...contentViolations);
    } catch (_) {
      // Binary files or deleted
    }
  }

  if (violations.length > 0) {
    console.error('\n🚫 ============================================================');
    console.error('🚫 COMMIT BLOCKED: SECURITY POLICY VIOLATIONS DETECTED');
    console.error('🚫 ============================================================');
    violations.forEach((v, idx) => {
      console.error(`\n[${idx + 1}] Rule: ${v.rule}`);
      console.error(`    File: ${v.filePath || v.file}`);
      if (v.secretType) console.error(`    Secret Type: ${v.secretType}`);
      if (v.masked) console.error(`    Detected Match: ${v.masked}`);
      if (v.message) console.error(`    Details: ${v.message}`);
    });
    console.error('\nAction Required: Remove the sensitive files or credentials and unstage them before committing.');
    console.error('============================================================\n');
    process.exit(1);
  }

  console.log(`✅ [Git Security] Pre-commit check passed for ${stagedFiles.length} staged file(s).`);
}

function runPrePush() {
  console.log('🔒 [Git Security] Executing pre-push verification on outgoing commits...');
  let commitsToCheck = [];
  try {
    // Check commits between origin/main (or HEAD~1) and HEAD
    let range = 'origin/main..HEAD';
    try {
      execSync('git rev-parse --verify origin/main', { stdio: 'ignore' });
    } catch {
      range = 'HEAD~1..HEAD';
    }

    const output = execSync(`git log ${range} --name-only --oneline --diff-filter=ACM`, { encoding: 'utf8' });
    commitsToCheck = Array.from(new Set(
      output.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.match(/^[0-9a-f]{7,40}\s/))
    ));
  } catch {
    commitsToCheck = [];
  }

  if (commitsToCheck.length === 0) {
    console.log('✅ [Git Security] No outgoing commit files to scan.');
    return;
  }

  const violations = [];

  for (const file of commitsToCheck) {
    const pathViolation = checkFilePath(file);
    if (pathViolation) {
      violations.push({ file, ...pathViolation });
      continue;
    }

    if (fs.existsSync(file)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const contentViolations = checkFileContent(file, content);
        violations.push(...contentViolations);
      } catch (_) {}
    }
  }

  if (violations.length > 0) {
    console.error('\n🚫 ============================================================');
    console.error('🚫 PUSH BLOCKED: SECURITY POLICY VIOLATIONS DETECTED');
    console.error('🚫 ============================================================');
    violations.forEach((v, idx) => {
      console.error(`\n[${idx + 1}] Rule: ${v.rule}`);
      console.error(`    File: ${v.filePath || v.file}`);
      if (v.secretType) console.error(`    Secret Type: ${v.secretType}`);
      if (v.masked) console.error(`    Detected Match: ${v.masked}`);
      if (v.message) console.error(`    Details: ${v.message}`);
    });
    console.error('\nAction Required: Rewriting or amending outgoing commits is required to remove protected files/secrets.');
    console.error('============================================================\n');
    process.exit(1);
  }

  console.log(`✅ [Git Security] Pre-push check passed for ${commitsToCheck.length} outgoing file(s).`);
}

function runFullScan() {
  console.log('🔒 [Git Security] Executing full repository audit on tracked files...');
  let trackedFiles = [];
  try {
    const output = execSync('git ls-files', { encoding: 'utf8' });
    trackedFiles = output.split('\n').map(s => s.trim()).filter(Boolean);
  } catch (err) {
    console.error('❌ [Git Security] Failed to list tracked files:', err.message);
    process.exit(1);
  }

  const violations = [];

  for (const file of trackedFiles) {
    const pathViolation = checkFilePath(file);
    if (pathViolation) {
      violations.push({ file, ...pathViolation });
      continue;
    }

    if (fs.existsSync(file)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const contentViolations = checkFileContent(file, content);
        violations.push(...contentViolations);
      } catch (_) {}
    }
  }

  if (violations.length > 0) {
    console.error('\n🚫 ============================================================');
    console.error('🚫 REPOSITORY SECURITY AUDIT FAILED: VIOLATIONS FOUND');
    console.error('🚫 ============================================================');
    violations.forEach((v, idx) => {
      console.error(`\n[${idx + 1}] Rule: ${v.rule}`);
      console.error(`    File: ${v.filePath || v.file}`);
      if (v.secretType) console.error(`    Secret Type: ${v.secretType}`);
      if (v.masked) console.error(`    Detected Match: ${v.masked}`);
      if (v.message) console.error(`    Details: ${v.message}`);
    });
    console.error('============================================================\n');
    process.exit(1);
  }

  console.log(`✅ [Git Security] Clean repository: All ${trackedFiles.length} tracked files conform to security policy.`);
}

// -------------------------------------------------------------
// Entry Point
// -------------------------------------------------------------
const args = process.argv.slice(2);
if (args.includes('--pre-commit')) {
  runPreCommit();
} else if (args.includes('--pre-push')) {
  runPrePush();
} else {
  runFullScan();
}
