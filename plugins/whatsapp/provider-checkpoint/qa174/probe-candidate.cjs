// Mounted read-only for qualification only; never copied into the image.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const expected = JSON.parse(fs.readFileSync('/opt/offline/expected.json', 'utf8'));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function inventory(root, relative = '') {
  const result = {};
  for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
    const key = relative ? `${relative}/${name}` : name;
    const file = path.join(root, key);
    const info = fs.lstatSync(file);
    assert.equal(info.isSymbolicLink(), false, key);
    if (info.isDirectory()) Object.assign(result, inventory(root, key));
    else {
      assert.ok(info.isFile(), key);
      assert.equal(info.uid, 0, key);
      assert.equal(info.mode & 0o777, 0o644, key);
      result[key] = sha(fs.readFileSync(file));
    }
  }
  return result;
}
assert.equal(process.version, expected.node_version);
assert.deepEqual(inventory('/app/dist'), expected.dist);
for (const [name, digest] of Object.entries(expected.dependency_files)) {
  assert.equal(sha(fs.readFileSync(`/app/${name}`)), digest, name);
}
const binary = fs.statSync('/app/gows');
assert.equal(binary.uid, 0);
assert.equal(binary.mode & 0o777, 0o755);
const receipt = JSON.parse(execFileSync('node', ['/opt/offline/probe-runtime.cjs'], {
  encoding: 'utf8', timeout: 110000,
}).trim().split('\n').at(-1));
receipt.candidate = {
  distFiles: Object.keys(expected.dist).length,
  distInventoryVerified: true,
  dependencyFilesVerified: Object.keys(expected.dependency_files),
  gowsMode: '0755',
};
// Include concrete native loader output/version, not only a success boolean.
receipt.nativeLibraries = {
  ldd: execFileSync('ldd', ['/app/gows'], { encoding: 'utf8' }),
  ffmpeg: execFileSync('ffmpeg', ['-version'], { encoding: 'utf8' }).split('\n')[0],
  tini: execFileSync('/usr/bin/tini', ['--version'], { encoding: 'utf8' }).trim(),
};
process.stdout.write(JSON.stringify(receipt) + '\n');
