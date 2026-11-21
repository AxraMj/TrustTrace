import { ApiError } from './http.js';
import { buildEvidence } from './evidence.js';
import {
  ACTIONS, ATTESTATION_STATUSES, AUDIT_TYPES, BUCKETS, FLAGS, SEVERITIES, WINDOWS, allowParams, cursorShapes, decodeCursor, encodeCursor, isUuid, parseEnum, parseEnumList,
  parseId, parseInteger, parseLimit, parseBool, parseRange, parseSearch, validateId,
} from './params.js';
import { EXTRACTOR_VERSION, MODEL_VERSION, POLICY_VERSION } from '../versions.js';

const READ = { auth: 'user' }; // analyst, supervisor, admin (all read-only in v1)
const SUPERVISION = { auth: 'user', roles: ['supervisor', 'admin'] };
const EVENT_TYPE_RE = /^[a-z][a-z0-9_]{0,39}$/;
const RANGE = ['window', 'from', 'to'];
const PAGE = ['limit', 'cursor'];

const meta = (clock, range, extra = {}) => ({ generatedAt: new Date(clock()).toISOString(), source: 'postgresql', window: range?.window ?? null, from: range?.from?.toISOString() ?? null, to: range?.to?.toISOString() ?? null, ...extra });
const notFound = (what) => new ApiError(404, `${what}_not_found`, `${what.replace('_', ' ')} not found`);

function eventTypes(url) {
  const raw = url.searchParams.get('eventType');
  if (!raw) return undefined;
  const parts = [...new Set(raw.split(',').map((s) => s.trim()).filter(Boolean))];
  if (!parts.length || parts.length > 10 || parts.some((p) => !EVENT_TYPE_RE.test(p))) throw new ApiError(400, 'invalid_parameter', 'eventType must list up to 10 event type names');
  return parts;
}
const caseKey = (params) => ({ accountId: validateId(params.accountId, 'accountId'), caseId: validateId(params.caseId, 'caseId') });

export function registerInvestigationRoutes(r) {
  // Static vocabulary the UI needs (not data): enums, windows, versions.
  r.add('GET', '/api/meta', READ, async ({ clock }) => ({
    body: {
      generatedAt: new Date(clock()).toISOString(), readOnly: true,
      severities: SEVERITIES, actions: ACTIONS, flags: FLAGS, windows: Object.keys(WINDOWS), buckets: BUCKETS, attestationStatuses: ATTESTATION_STATUSES, auditTypes: AUDIT_TYPES,
      versions: { model: MODEL_VERSION, extractor: EXTRACTOR_VERSION, policy: POLICY_VERSION },
    },
  }));

  // ---- Dashboard summary ----
  r.add('GET', '/api/summary', READ, async ({ url, deps, clock }) => {
    allowParams(url, [...RANGE, 'bucket']);
    const range = parseRange(url, { defaultWindow: '24h', now: clock() });
    const spanMs = range.from ? range.to - range.from : Infinity;
    const bucket = parseEnum(url, 'bucket', BUCKETS, spanMs <= 3 * 86400e3 ? 'hour' : 'day');
    return { body: { meta: meta(clock, range, { bucket }), ...(await deps.data.summary({ from: range.from, to: range.to, bucket })) } };
  });

  // ---- Risk alerts ----
  r.add('GET', '/api/alerts', READ, async ({ url, deps, clock }) => {
    allowParams(url, ['q', 'severity', 'action', 'eventType', 'flag', ...RANGE, ...PAGE]);
    const range = parseRange(url, { defaultWindow: '7d', now: clock() });
    const limit = parseLimit(url);
    const after = decodeCursor(url.searchParams.get('cursor'), cursorShapes.decision);
    const res = await deps.data.listAlerts({
      q: parseSearch(url), severities: parseEnumList(url, 'severity', SEVERITIES), actions: parseEnumList(url, 'action', ACTIONS),
      eventTypes: eventTypes(url), flags: parseEnumList(url, 'flag', FLAGS), from: range.from, to: range.to, limit, after,
    });
    return { body: { meta: meta(clock, range), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  });

  // ---- Decision explanation ----
  r.add('GET', '/api/decisions/:id', READ, async ({ params, url, deps, clock }) => {
    allowParams(url, []);
    if (!isUuid(params.id)) throw new ApiError(400, 'invalid_parameter', 'decision id must be a UUID');
    const d = await deps.data.getDecision(params.id);
    if (!d) throw notFound('decision');
    return { body: { meta: meta(clock), ...d } };
  });
  r.add('GET', '/api/decisions/:id/evidence', READ, async ({ params, url, deps, clock }) => {
    allowParams(url, []);
    if (!isUuid(params.id)) throw new ApiError(400, 'invalid_parameter', 'decision id must be a UUID');
    const rec = await deps.data.decisionRecord(params.id);
    if (!rec) throw notFound('decision');
    const ids = [...new Set([...rec.retrieved.map((m) => m.id), ...rec.contributions.map((c) => c.memoryId).filter(Boolean)])];
    return { body: { meta: meta(clock), decisionId: rec.id, ...buildEvidence([rec], await deps.data.writersFor(ids)) } };
  });

  // ---- Cases ----
  r.add('GET', '/api/cases', READ, async ({ url, deps, clock }) => {
    allowParams(url, ['q', 'severity', ...RANGE, ...PAGE]);
    const range = parseRange(url, { defaultWindow: '30d', now: clock() });
    const res = await deps.data.listCases({
      q: parseSearch(url), severities: parseEnumList(url, 'severity', SEVERITIES), from: range.from, to: range.to, limit: parseLimit(url),
      after: decodeCursor(url.searchParams.get('cursor'), cursorShapes.case),
    });
    return { body: { meta: meta(clock, range), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  });

  const withCase = (handler) => async (ctx) => {
    const { accountId, caseId } = caseKey(ctx.params);
    const c = await ctx.deps.data.getCase(accountId, caseId);
    if (!c) throw notFound('case');
    return handler({ ...ctx, accountId, caseId, caseHeader: c });
  };

  r.add('GET', '/api/cases/:accountId/:caseId', READ, withCase(async ({ url, caseHeader, clock }) => {
    allowParams(url, []);
    return { body: { meta: meta(clock), ...caseHeader } };
  }));
  r.add('GET', '/api/cases/:accountId/:caseId/timeline', READ, withCase(async ({ url, accountId, caseId, deps, clock }) => {
    allowParams(url, ['limit']);
    const t = await deps.data.caseTimeline(accountId, caseId, { limit: parseLimit(url, { def: 200, max: 500 }) });
    return { body: { meta: meta(clock), accountId, caseId, ...t } };
  }));
  r.add('GET', '/api/cases/:accountId/:caseId/decisions', READ, withCase(async ({ url, accountId, caseId, deps, clock }) => {
    allowParams(url, ['limit', 'cursor']);
    const res = await deps.data.listAlerts({
      accountId, caseId, from: null, to: new Date(clock() + 60_000), limit: parseLimit(url), after: decodeCursor(url.searchParams.get('cursor'), cursorShapes.decision),
    });
    return { body: { meta: meta(clock), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  }));
  r.add('GET', '/api/cases/:accountId/:caseId/evidence', READ, withCase(async ({ url, accountId, caseId, deps, clock }) => {
    allowParams(url, []);
    const decisions = await deps.data.caseDecisions(accountId, caseId, { limit: 200 });
    const ids = [...new Set(decisions.flatMap((d) => [...d.retrieved.map((m) => m.id), ...d.contributions.map((c) => c.memoryId).filter(Boolean)]))];
    return { body: { meta: meta(clock), accountId, caseId, decisionCount: decisions.length, ...buildEvidence(decisions, await deps.data.writersFor(ids)) } };
  }));
  r.add('GET', '/api/cases/:accountId/:caseId/verification', READ, withCase(async ({ url, accountId, caseId, deps, clock }) => {
    allowParams(url, []);
    const [attestations, rejections] = await Promise.all([
      deps.data.caseAttestations(accountId, caseId),
      deps.data.listRejections({ accountId, caseId, from: null, to: new Date(clock() + 60_000), limit: 200 }),
    ]);
    return { body: { meta: meta(clock), accountId, caseId, attestations, rejections: rejections.items, rejectionsTruncated: rejections.truncated } };
  }));
  r.add('GET', '/api/cases/:accountId/:caseId/activity', READ, withCase(async ({ url, accountId, caseId, deps, clock }) => {
    allowParams(url, ['limit', 'cursor']);
    const res = await deps.data.listActivity({
      accountId, caseId, from: null, to: new Date(clock() + 60_000), limit: parseLimit(url), after: decodeCursor(url.searchParams.get('cursor'), cursorShapes.activity),
    });
    return { body: { meta: meta(clock), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  }));

  // ---- Agent activity ----
  r.add('GET', '/api/activity', READ, async ({ url, deps, clock }) => {
    allowParams(url, ['agentId', 'kind', 'accountId', 'caseId', 'decisionId', 'ok', ...RANGE, ...PAGE]);
    const range = parseRange(url, { defaultWindow: '24h', now: clock() });
    const decisionId = parseId(url, 'decisionId');
    if (decisionId && !isUuid(decisionId)) throw new ApiError(400, 'invalid_parameter', 'decisionId must be a UUID');
    const res = await deps.data.listActivity({
      agentId: parseId(url, 'agentId', { max: 100 }), kind: parseId(url, 'kind', { max: 100 }), accountId: parseId(url, 'accountId'), caseId: parseId(url, 'caseId'),
      decisionId, ok: parseBool(url, 'ok'), from: range.from, to: range.to, limit: parseLimit(url), after: decodeCursor(url.searchParams.get('cursor'), cursorShapes.activity),
    });
    return { body: { meta: meta(clock, range), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  });

  // ---- Verification status ----
  r.add('GET', '/api/verification/attestations', READ, async ({ url, deps, clock }) => {
    allowParams(url, ['status', 'kind', 'accountId', 'caseId', ...RANGE, ...PAGE]);
    const range = parseRange(url, { defaultWindow: '30d', now: clock() });
    const res = await deps.data.listAttestations({
      status: parseEnumList(url, 'status', ATTESTATION_STATUSES), kind: parseId(url, 'kind', { max: 100 }), accountId: parseId(url, 'accountId'), caseId: parseId(url, 'caseId'),
      from: range.from, to: range.to, limit: parseLimit(url), after: decodeCursor(url.searchParams.get('cursor'), cursorShapes.attestation),
    });
    return { body: { meta: meta(clock, range), items: res.items, nextCursor: res.next ? encodeCursor(res.next) : null } };
  });
  r.add('GET', '/api/verification/rejections', READ, async ({ url, deps, clock }) => {
    allowParams(url, ['reason', 'accountId', 'caseId', ...RANGE, 'limit']);
    const range = parseRange(url, { defaultWindow: '30d', now: clock() });
    const res = await deps.data.listRejections({
      reason: parseId(url, 'reason', { max: 60 }), accountId: parseId(url, 'accountId'), caseId: parseId(url, 'caseId'), from: range.from, to: range.to, limit: parseLimit(url),
    });
    return { body: { meta: meta(clock, range), items: res.items, truncated: res.truncated } };
  });
  r.add('GET', '/api/verification/keys', READ, async ({ deps, clock, url }) => {
    allowParams(url, []);
    return { body: { meta: meta(clock), items: await deps.data.verifierKeys() } };
  });

  // ---- Audit history (supervisors and admins; chain VERIFICATION stays admin-only in routes.js) ----
  r.add('GET', '/api/audit', SUPERVISION, async ({ url, deps, clock }) => {
    allowParams(url, ['type', 'refId', 'afterSeq', 'limit']);
    const type = parseEnum(url, 'type', AUDIT_TYPES, undefined);
    const res = await deps.data.listAudit({
      type, refId: parseId(url, 'refId'), afterSeq: parseInteger(url, 'afterSeq', { def: 0 }), limit: parseLimit(url, { def: 100, max: 500 }),
    });
    return { body: { meta: meta(clock), items: res.items, nextAfterSeq: res.nextAfterSeq } };
  });
  r.add('GET', '/api/audit/head', SUPERVISION, async ({ deps, clock, url }) => {
    allowParams(url, []);
    return { body: { meta: meta(clock), ...(await deps.data.auditHead()) } };
  });
}
