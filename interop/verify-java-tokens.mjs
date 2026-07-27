// ovid4j — verifies Java-minted tokens with the TypeScript reference library.
// Usage: node interop/verify-java-tokens.mjs [path-to-ovid-dist-index.js]
// Prereq: `mvn test` (writes target/interop/java-tokens.json), and
//         `npm install && npm run build` in the ovid repo.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distPath = resolve(here, process.argv[2] ?? '../../ovid/dist/index.js');
const { verifyOvid, importPublicKeyBase64 } = await import(pathToFileURL(distPath).href);

const file = resolve(here, '../target/interop/java-tokens.json');
const { rootPublicKey, tokens } = JSON.parse(readFileSync(file, 'utf8'));
const trustedRoot = await importPublicKeyBase64(rootPublicKey);

let failures = 0;
for (const [name, { jwt, chain }] of Object.entries(tokens)) {
  const result = await verifyOvid(jwt, { trustedRoots: [trustedRoot] });
  const chainOk = JSON.stringify(result.chain) === JSON.stringify(chain);
  if (result.valid && chainOk) {
    console.log(`ok   ${name}: principal=${result.principal} chain=[${result.chain.join(' -> ')}]`);
  } else {
    failures++;
    console.error(`FAIL ${name}: valid=${result.valid} chain=${JSON.stringify(result.chain)}`);
  }
}

// A Java token must NOT verify under a foreign root.
const foreign = await importPublicKeyBase64('hv9Kb2kBKPZ_G8hCYIkC0MDde7QpF8XvKAHUOnHT-UE');
const foreignResult = await verifyOvid(tokens.root.jwt, { trustedRoots: [foreign] });
if (foreignResult.valid) {
  failures++;
  console.error('FAIL root token verified under a foreign trusted root');
} else {
  console.log('ok   foreign-root rejection');
}

process.exit(failures === 0 ? 0 : 1);
