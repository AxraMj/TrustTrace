// Connectivity check: npm run check
// Verifies auth, that the documented tools exist, and that the TrustTrace datapack is usable.
import { loadConfig, loadDotEnv } from './config.js';
import { MekoClient } from './meko/client.js';
import { openSession } from './session.js';
import { TrustTraceError } from './errors.js';

const REQUIRED_TOOLS = ['datapack_search', 'datapack_create', 'conversation_create', 'conversation_delete', 'memory_add', 'memory_search', 'memory_delete_by_id'];

try {
  loadDotEnv();
  const config = loadConfig();
  console.log(`Connecting to ${config.mcpUrl} ...`);
  const client = await new MekoClient(config).connect();
  console.log('OK  authenticated + MCP session established');

  const tools = (await client.listTools()).map((t) => t.name);
  console.log(`OK  server exposes ${tools.length} tools`);
  const missing = REQUIRED_TOOLS.filter((t) => !tools.includes(t));
  if (missing.length) throw new Error(`Missing required Meko tools: ${missing.join(', ')}`);
  console.log(`OK  required tools present: ${REQUIRED_TOOLS.join(', ')}`);

  await client.close();

  const s = await openSession();
  console.log(`OK  datapack "${s.datapack.name}" ${s.datapack.created ? 'CREATED' : 'already existed'} (id: ${s.datapack.id})`);
  await s.client.close();
} catch (err) {
  console.error(`FAIL ${err.name}: ${err.message}`);
  if (!(err instanceof TrustTraceError)) console.error(err.stack);
  process.exitCode = 1;
}
