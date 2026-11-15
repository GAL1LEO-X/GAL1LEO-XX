// Runtime-only qualification guard; never copy into the production image.
const fs = require('node:fs');
const Module = require('node:module');
const assert = require('node:assert/strict');
const path = require('node:path');
const markerRoot = process.env.OFFLINE_MARKER_ROOT;
assert.ok(markerRoot && path.isAbsolute(markerRoot), 'Explicit qualification marker directory required');
fs.mkdirSync(markerRoot, { recursive: true });

function block(operation) {
  fs.appendFileSync(`${markerRoot}/blocked.jsonl`, JSON.stringify({ operation: operation }) + '\n');
  throw new Error(`Offline qualification blocked lifecycle/RPC: ${operation}`);
}

function armPrototype(target, methods) {
  if (!target || target.prototype.__offlineLifecycleGuard) return;
  Object.defineProperty(target.prototype, '__offlineLifecycleGuard', { value: true });
  for (const name of methods) {
    if (typeof target.prototype[name] === 'function') {
      target.prototype[name] = function () { return block(`${target.name}.${name}`); };
    }
  }
  fs.appendFileSync(`${markerRoot}/armed.jsonl`, JSON.stringify({ class: target.name }) + '\n');
}

const load = Module._load;
Module._load = function (request, parent, isMain) {
  const exported = load.call(this, request, parent, isMain);
  if (exported?.SessionManagerCore) {
    armPrototype(exported.SessionManagerCore, ['start', 'restart', 'save', 'delete', 'unpair', 'logout']);
  }
  if (exported?.WhatsappSessionGoWSCore) {
    armPrototype(exported.WhatsappSessionGoWSCore, ['start', 'unpair']);
  }
  if (request === '@grpc/grpc-js' && exported.Client && !exported.Client.prototype.__offlineRpcGuard) {
    Object.defineProperty(exported.Client.prototype, '__offlineRpcGuard', { value: true });
    const unary = exported.Client.prototype.makeUnaryRequest;
    exported.Client.prototype.makeUnaryRequest = function (method, ...args) {
      if (method !== '/messages.MessageService/GetABContract') return block(method);
      return unary.call(this, method, ...args);
    };
    for (const method of ['makeClientStreamRequest', 'makeServerStreamRequest', 'makeBidiStreamRequest']) {
      exported.Client.prototype[method] = function (path) { return block(path); };
    }
  }
  return exported;
};
