import fs from 'node:fs';
import { webcrypto } from 'node:crypto';

// Paths resolve against this script, not against whoever ran it.
const wasmDir = new URL('../internal/server/static/wasm/', import.meta.url);
globalThis.crypto ??= webcrypto;
globalThis.fs = fs;
await import(new URL('wasm_exec.js', wasmDir));
const go = new Go();
const { instance } = await WebAssembly.instantiate(fs.readFileSync(new URL('ceremony.wasm', wasmDir)), go.importObject);
go.run(instance); // main blocks on select{}; read the global on the next tick
await new Promise(r => setTimeout(r, 0));
const r = globalThis.kyCeremony(3, 5);
if (r.error) throw new Error(r.error);
if (!/^[0-9a-f]{64}$/.test(r.key_id)) throw new Error('key_id ' + r.key_id);
if (Buffer.from(r.public_key_b64, 'base64').length !== 1216) throw new Error('public key length');
if (r.shares.length !== 5 || !r.shares.every(s => s.startsWith('ky2-'))) throw new Error('shares malformed');
console.log('ceremony.wasm OK', r.key_id);
process.exit(0);
