// ovid4j — generates golden fixtures with the TypeScript reference library.
// Usage: node interop/generate-ts-fixtures.mjs [path-to-ovid-dist-index.js]
// Prereq: `npm install && npm run build` in the ovid repo.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distPath = resolve(here, process.argv[2] ?? '../../ovid/dist/index.js');
const { generateKeypair, createOvid, exportPublicKeyBase64 } =
  await import(pathToFileURL(distPath).href);

const LONG_TTL = 10 * 365 * 24 * 3600; // fixtures must not expire under CI clocks
const MANDATE = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

const rootKeys = await generateKeypair();
const root = await createOvid({
  issuerKeys: rootKeys,
  issuer: 'ts-interop',
  agentId: 'ts-interop/root',
  mandate: { ...MANDATE },
  ttlSeconds: LONG_TTL,
});
const depth2 = await createOvid({
  issuerKeys: root.keys,
  issuerOvid: root,
  agentId: 'ts-interop/root/child',
  mandate: { ...MANDATE },
  ttlSeconds: LONG_TTL - 100,
});
const depth3 = await createOvid({
  issuerKeys: depth2.keys,
  issuerOvid: depth2,
  agentId: 'ts-interop/root/child/grandchild',
  mandate: { ...MANDATE },
  ttlSeconds: LONG_TTL - 200,
});

const tokenEntry = (t) => ({
  jwt: t.jwt,
  exp: t.claims.exp,
  chain: t.claims.authorization_details[0].parent_chain.map((l) => l.sub),
});

const fixtures = {
  generatedAt: Math.floor(Date.now() / 1000),
  generator: '@clawdreyhepburn/ovid (dist build)',
  rootPublicKey: await exportPublicKeyBase64(rootKeys.publicKey),
  tokens: { root: tokenEntry(root), depth2: tokenEntry(depth2), depth3: tokenEntry(depth3) },
};

const outFile = resolve(here, '../src/test/resources/interop/ts-fixtures.json');
mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(fixtures, null, 2) + '\n');
console.log(`wrote ${outFile}`);
