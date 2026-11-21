import { loadConfig, loadDotEnv } from './config.js';
import { MekoClient } from './meko/client.js';
import { MemoryStore, createConversation, ensureDatapack } from './meko/memory.js';

const SETUP_AGENT = 'trusttrace_setup';

/** Load .env, validate config, connect to Meko, resolve/create the datapack, return a MemoryStore. */
export async function openSession(env) {
  if (!env) loadDotEnv();
  const config = loadConfig(env ?? process.env);
  const client = await new MekoClient(config).connect();

  // Datapack tools need a conversation_id too. Use ONE stable setup conversation (session_id
  // dedup) in the account's default datapack, so repeated runs never create new conversations.
  const setupId = await createConversation(client, {
    agentId: SETUP_AGENT,
    title: 'TrustTrace setup',
    sessionId: 'trusttrace-setup',
  });
  const datapack = await ensureDatapack(client, config.datapack, setupId);
  return { config, client, datapack, store: new MemoryStore(client, datapack.id) };
}
