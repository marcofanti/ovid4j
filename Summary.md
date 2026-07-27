# ovid4j

**Source:** local project (Java port of https://github.com/clawdreyhepburn/ovid)
**Stack:** Java 26 (Maven, Jackson, JUnit 5)

Unofficial Java port of OVID — cryptographic identity documents for AI agents
(Ed25519-signed JWTs with Cedar mandates and verifiable delegation chains).
Wire-compatible with `@clawdreyhepburn/ovid` protocol 0.4.0; interop is tested
in both directions against the TypeScript reference library (golden fixtures in,
`interop/verify-java-tokens.mjs` out). Apache-2.0 with upstream attribution in
NOTICE; intentional deviations (legacy tokens rejected, `typ` enforced) are
documented in README.md.

## Running it

```bash
mvn test   # 75 tests incl. TS-fixture interop
```
