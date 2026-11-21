import { MissingCredentialsError } from './errors.js';

const DEFAULT_URL = 'https://mcp.mekodata.ai/mcp';
const DEFAULT_DATAPACK = 'trusttrace-test';

/** Load .env into process.env if present (Node >= 20.12). Existing env vars win. */
export function loadDotEnv(path = '.env') {
  try {
    process.loadEnvFile(path);
  } catch (err) {
    if (err?.code !== 'ENOENT') throw err;
  }
}

/**
 * Read configuration from an env object. Never logs or returns the key in errors.
 * @throws {MissingCredentialsError}
 */
export function loadConfig(env = process.env) {
  const apiKey = (env.MEKO_API_KEY ?? '').trim();
  if (!apiKey) {
    throw new MissingCredentialsError(
      'MEKO_API_KEY is not set. Create a key in the Meko portal (Settings > API Keys), ' +
        'then put MEKO_API_KEY=mko_tkn_... in .env (see .env.example).',
    );
  }
  if (!apiKey.startsWith('mko_tkn_')) {
    throw new MissingCredentialsError(
      'MEKO_API_KEY is malformed: Meko API keys start with "mko_tkn_".',
    );
  }
  return Object.freeze({
    apiKey,
    mcpUrl: (env.MEKO_MCP_URL ?? '').trim() || DEFAULT_URL,
    datapack: (env.MEKO_DATAPACK ?? '').trim() || DEFAULT_DATAPACK,
  });
}
