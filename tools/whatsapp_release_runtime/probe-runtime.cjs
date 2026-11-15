// Runs only inside a network-disabled, empty, temporary qualification container.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { createRequire } = require('node:module');
const path = require('node:path');
const appRoot = process.env.OFFLINE_APP_ROOT || '/app';
const markerRoot = process.env.OFFLINE_MARKER_ROOT;
assert.ok(markerRoot && path.isAbsolute(markerRoot));
const appRequire = createRequire(path.join(appRoot, 'package.json'));
const grpc = appRequire('@grpc/grpc-js');
const { messages } = appRequire(path.join(appRoot, 'dist/core/engines/gows/grpc/gows.js'));
const { Ffmpeg } = appRequire(path.join(appRoot, 'dist/core/utils/ffmpeg.js'));
const pino = appRequire('pino');

function wav() {
  const samples = 8000;
  const data = Buffer.alloc(44 + samples * 2);
  data.write('RIFF', 0);
  data.writeUInt32LE(data.length - 8, 4);
  data.write('WAVEfmt ', 8);
  data.writeUInt32LE(16, 16);
  data.writeUInt16LE(1, 20);
  data.writeUInt16LE(1, 22);
  data.writeUInt32LE(samples, 24);
  data.writeUInt32LE(samples * 2, 28);
  data.writeUInt16LE(2, 32);
  data.writeUInt16LE(16, 34);
  data.write('data', 36);
  data.writeUInt32LE(samples * 2, 40);
  for (let i = 0; i < samples; i++) {
    data.writeInt16LE(Math.round(2000 * Math.sin(2 * Math.PI * 440 * i / samples)), 44 + i * 2);
  }
  return data;
}

async function main() {
  const result = { scope: 'isolated-no-account-runtime', liveWhatsApp: false, node: { version: process.version, arch: process.arch, platform: process.platform } };
  assert.equal(process.getuid(), Number(process.env.OFFLINE_EXPECTED_UID));
  assert.equal(process.getgid(), Number(process.env.OFFLINE_EXPECTED_UID));
  assert.notEqual(process.getuid(), 0);
  result.uid = process.getuid();
  const endpoint = 'http://127.0.0.1:3000/api/sessions?all=true';
  const unauthorized = await fetch(endpoint, { signal: AbortSignal.timeout(5000) });
  assert.equal(unauthorized.status, 401);
  result.unauthenticatedStatus = unauthorized.status;
  const authenticated = await fetch(endpoint, {
    headers: { 'X-Api-Key': process.env.WAHA_API_KEY },
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(authenticated.status, 200);
  assert.deepEqual(await authenticated.json(), []);
  result.authenticatedStatus = authenticated.status;
  result.sessions = [];

  const client = new messages.MessageServiceClient(
    `unix:${process.env.WAHA_GOWS_SOCKET}`,  grpc.credentials.createInsecure(), { 'grpc.enable_retries': 0 },
  );
  try {
    const contract = await new Promise(function (resolve, reject) {
      client.GetABContract(new messages.Empty(), { deadline: Date.now() + 5000 }, function (error, response) {
        if (error) reject(error); else resolve(response.toObject());
      });
    });
    assert.equal(contract.version, 'gows-ab-v1');
    const operations = [
      'contacts_get_about', 'contacts_block', 'contacts_unblock',
      'chats_archive_chat', 'chats_unarchive_chat', 'messages_set_star',
      'chats_pin_message', 'chats_unpin_message',
    ].sort();
    assert.deepEqual([...contract.operations].sort(), operations);
    result.abContract = contract;
  } finally {
    client.close();
  }

  const binary = fs.readFileSync(path.join(appRoot, 'gows'));
  const digest = crypto.createHash('sha256').update(binary).digest('hex');
  assert.equal(digest, process.env.OFFLINE_EXPECTED_GOWS_SHA256);
  assert.equal(binary.subarray(0, 4).toString('hex'), '7f454c46');
  assert.equal(binary[4], 2); // ELF64
  assert.equal(binary.readUInt16LE(18), 62); // x86-64
  const loader = execFileSync('ldd', [path.join(appRoot, 'gows')], { encoding: 'utf8' });
  assert.doesNotMatch(loader, /not found/);
  execFileSync(path.join(appRoot, 'gows'), ['--help'], { stdio: 'pipe' });
  result.gows = { sha256: digest, elf: 'linux-amd64', loader: 'resolved', help: 'passed' };

  const input = wav();
  const converter = new Ffmpeg('offline-qualification', pino({ level: 'silent' }));
  const converted = await converter.voice(input);
  assert.equal(converted.subarray(0, 4).toString(), 'OggS');
  const file = path.join(markerRoot, 'converted.ogg');
  await fsp.writeFile(file, converted);
  const probe = JSON.parse(execFileSync('ffprobe', [
    '-v', 'error', '-show_format', '-show_streams', '-of', 'json', file,
  ], { encoding: 'utf8' }));
  assert.equal(probe.format.format_name, 'ogg');
  assert.equal(probe.streams[0].codec_name, 'opus');
  assert.equal(probe.streams[0].sample_rate, '48000');
  assert.equal(probe.streams[0].channels, 1);
  assert.ok(Number(probe.format.duration) > 0.9);
  execFileSync('ffmpeg', ['-v', 'error', '-i', file, '-f', 'null', '-'], { stdio: 'pipe' });
  result.audio = {
    inputSha256: crypto.createHash('sha256').update(input).digest('hex'),
    outputSha256: crypto.createHash('sha256').update(converted).digest('hex'),
    format: 'ogg', codec: 'opus', sampleRate: 48000, channels: 1,
    decoded: true, whatsappPlaybackVerified: false,
  };

  const markers = markerRoot;
  assert.equal(fs.existsSync(`${markers}/blocked.jsonl`), false);
  const guards = fs.readFileSync(`${markers}/armed.jsonl`, 'utf8').trim().split('\n').map(JSON.parse);
  assert.ok(guards.some(function (value) { return value.class === 'SessionManagerCore'; }));
  assert.ok(guards.some(function (value) { return value.class === 'WhatsappSessionGoWSCore'; }));
  result.lifecycleGuard = { armed: guards, attempts: 0 };
  assert.equal(fs.existsSync(path.join(appRoot, 'dist/dashboard')), false);
  assert.equal(fs.existsSync(path.join(appRoot, 'dist/plus')), false);
  result.excludedAssets = ['dashboard', 'plus'];
  assert.equal(fs.existsSync('/run/secrets/ca_bundle'), false);
  for (const variable of ['NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO', 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) {
    assert.ok(!process.env[variable], `Build-only environment must be absent: ${variable}`);
  }
  result.trust = { buildSecretAbsent: true, buildProxyEnvironmentAbsent: true };
  if (process.env.OFFLINE_EXCLUDED_CA_SHA256) {
    const certificates = fs.readFileSync('/etc/ssl/certs/ca-certificates.crt', 'utf8')
      .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    assert.ok(certificates?.length);
    const fingerprints = certificates.map(function (pem) {
      return crypto.createHash('sha256').update(new crypto.X509Certificate(pem).raw).digest('hex');
    });
    assert.equal(fingerprints.includes(process.env.OFFLINE_EXCLUDED_CA_SHA256), false);
    result.trust = { buildSecretAbsent: true, buildProxyEnvironmentAbsent: true, excludedPublicCaSha256: process.env.OFFLINE_EXCLUDED_CA_SHA256, excludedPublicCaPresent: false, certificatesCount: certificates.length };
  }
  const finalSessions = await fetch(endpoint, { headers: { 'X-Api-Key': process.env.WAHA_API_KEY }, signal: AbortSignal.timeout(5000) });
  assert.equal(finalSessions.status, 200);
  assert.deepEqual(await finalSessions.json(), []);
  assert.equal(fs.existsSync(`${markers}/blocked.jsonl`), false);
  process.stdout.write(JSON.stringify(result) + '\n');
}

main().catch(function (error) {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
