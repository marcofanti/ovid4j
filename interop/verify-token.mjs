// ovid4j — verifies ONE token with the TypeScript reference library.
// Usage: echo '{"jwt": "...", "rootPublicKey": "..."}' | node interop/verify-token.mjs [dist]
// Prints the verify result as JSON: {"valid": bool, "principal"?, "chain"?}.
// Prereq: `npm install && npm run build` in the ovid repo (../../ovid by default).
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distPath = resolve(here, process.argv[2] ?? '../../ovid/dist/index.js');
const { verifyOvid, importPublicKeyBase64 } = await import(pathToFileURL(distPath).href);

const stdin = await new Promise((done) => {
  let data = '';
  process.stdin.on('data', (chunk) => (data += chunk));
  process.stdin.on('end', () => done(data));
});
const { jwt, rootPublicKey } = JSON.parse(stdin);

const trustedRoot = await importPublicKeyBase64(rootPublicKey);
const result = await verifyOvid(jwt, { trustedRoots: [trustedRoot] });
console.log(JSON.stringify({
  valid: result.valid,
  principal: result.principal ?? null,
  chain: result.chain ?? null,
}));
