#!/usr/bin/env node
// Candidate metadata export for six repaired contracts. No Nest application,
// constructor injection, bootstrap, listen, session or transport is invoked.
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const assert = require('node:assert/strict');
const [root, destination] = process.argv.slice(2);
assert.ok(root && destination, 'Usage: node export_candidate_openapi.cjs WAHA_ROOT NEW_OUTPUT.json');
const requireSource = Module.createRequire(path.resolve(root, 'package.json'));
const { SwaggerScanner } = requireSource('@nestjs/swagger/dist/swagger-scanner');
const { SwaggerTransformer } = requireSource('@nestjs/swagger/dist/swagger-transformer');
const { ApplicationConfig } = requireSource('@nestjs/core/application-config');
const scanner = new SwaggerScanner();
const applicationConfig = new ApplicationConfig();
const operations = new Set([
  'ChatsController_readChatMessages', 'ChattingController_sendContactVcard',
  'ChannelsController_searchByView', 'ChannelsController_searchByText',
  'LabelsController_create', 'LabelsController_update',
]);
const routes = [];
for (const [file, name] of [
  ['chats', 'ChatsController'], ['chatting', 'ChattingController'],
  ['channels', 'ChannelsController'], ['labels', 'LabelsController'],
]) {
  const type = requireSource(path.resolve(root, 'dist/api/' + file + '.controller.js'))[name];
  assert.equal(typeof type, 'function');
  const wrapper = {metatype: type, instance: Object.create(type.prototype)};
  routes.push(...scanner.explorer.exploreController(wrapper, applicationConfig, '', '')
    .filter(route => operations.has(route.root.operationId)));
}
assert.equal(routes.length, operations.size);
const document = {
  openapi: '3.0.0',
  info: {title: 'QA174 candidate compiled-controller metadata (six selected operations)', version: 'qa174-local'},
  ...new SwaggerTransformer().normalizePaths(routes),
  components: {schemas: scanner.explorer.getSchemas()},
  'x-qa174-provenance': 'Selected real compiled controller/DTO metadata; not the historical full OpenAPI or a running provider response. Controller constructors and methods were not invoked.',
};
fs.writeFileSync(destination, JSON.stringify(document, null, 2) + '\n', {flag: 'wx'});
process.stdout.write(JSON.stringify({output: destination, selected_operations: routes.map(route => route.root.operationId)}) + '\n');
