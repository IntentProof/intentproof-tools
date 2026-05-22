#!/usr/bin/env node
/**
 * Read one JSON value from stdin, strip signature, emit JCS canonical UTF-8.
 * Usage: node node-canonicalize.mjs <path-to-sdk-root-with-dist>
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const sdkRoot = process.argv[2];
if (!sdkRoot) {
  process.stderr.write('usage: node-canonicalize.mjs <sdk-root>\n');
  process.exit(2);
}

const require = createRequire(`${sdkRoot}/package.json`);
const { canonicalizeEvent } = require(`${sdkRoot}/dist/signing.js`);

const raw = readFileSync(0, 'utf8');
const value = JSON.parse(raw);
process.stdout.write(canonicalizeEvent(value));
