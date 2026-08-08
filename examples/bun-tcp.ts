/** Node's TCP API is available in Bun; the adapter remains outside the isomorphic entrypoint. */
import { Networks } from "../src/networks/networks.ts";
import { connectNodeTcp } from "../src/node.ts";
import { Protocol } from "../src/session/protocol.ts";

export { connectNodeTcp, Networks, Protocol };

const duplex = await connectNodeTcp({
  host: process.env.BITCOIN_HOST ?? "seed.signet.bitcoin.sprovoost.nl",
  port: Networks.signet.defaultPort,
});
const protocol = await Protocol.connect(duplex, {
  role: "initiator",
  network: Networks.signet,
});
console.log(`BIP-324 session established: ${protocol.sessionId.length} byte session ID`);
await protocol.close();
