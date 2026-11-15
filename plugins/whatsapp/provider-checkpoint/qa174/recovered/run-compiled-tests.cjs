// Read-only harness: resolve reviewed tests against the actual candidate /app.
const fs = require('node:fs');
const Module = require('node:module');
const filename = '/app/checkpoints/offline-ab/qa174-compiled.test.cjs';
const mod = new Module(filename, module);
mod.filename = filename;
mod.paths = Module._nodeModulePaths('/app/checkpoints/offline-ab');
mod._compile(fs.readFileSync('/opt/offline/qa174-compiled.test.cjs', 'utf8'), filename);
