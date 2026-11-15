// Compare installed versions at each lockfile location, not just semver ranges.
// No npm installs, scripts, network calls or package imports.
const fs = require('node:fs');
const path = require('node:path');
const root = process.cwd();
try {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== 'object') {
    throw Error('Expected package-lock v3 packages inventory');
  }
  let count = 0;
  for (const [location, expected] of Object.entries(lock.packages)) {
    if (location === '') continue;
    if (!location.startsWith('node_modules/') || location.includes('\\') ||
        location.split('/').some(part => ['', '.', '..'].includes(part)) ||
        expected.link || typeof expected.version !== 'string') {
      throw Error('Unsupported lockfile package location or link');
    }
    const manifest = path.join(root, location, 'package.json');
    if (!fs.existsSync(manifest) && expected.optional === true) continue;
    const actual = JSON.parse(fs.readFileSync(manifest, 'utf8'));
    if (actual.version !== expected.version) throw Error('Installed package version differs from lock');
    count++;
  }
  console.log(`PASS exact npm lock inventory (${count} installed packages).`);
} catch (_) {
  // Never echo package contents, registry URLs or credentials from malformed input.
  console.error('FAIL installed npm inventory differs from package-lock or lock format is unsupported.');
  process.exitCode = 1;
}
