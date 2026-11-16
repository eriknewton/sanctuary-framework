// Real isolated signer STATUS bytes for the ordinary checkpoint transport fixture.
import { serviceFixture } from "../../../server/test/fixtures/k1-service.js";
import { canonicalBytes } from "../../../server/src/signing/contract.js";

async function main() {
  const fixture = await serviceFixture();
  try {
    if (await fixture.ceremony() !== 0) throw new Error("isolated unlock refused");
    const status = await fixture.client.status();
    const bytes = Buffer.from(canonicalBytes(status));
    if (!Buffer.concat(fixture.frames).includes(bytes)) throw new Error("STATUS bytes absent from real transport");
    process.stdout.write(bytes);
  } finally {
    await fixture.close();
  }
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
