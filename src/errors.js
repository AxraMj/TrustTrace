export class TrustTraceError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = this.constructor.name;
  }
}

/** MEKO_API_KEY (or other required config) is absent or malformed. */
export class MissingCredentialsError extends TrustTraceError {}

/** Base class for every failure talking to Meko. */
export class MekoError extends TrustTraceError {}

/** Meko rejected the credentials (HTTP 401/403 or auth-shaped tool error). */
export class MekoAuthError extends MekoError {}

/** Could not reach Meko at all (DNS, TLS, timeout, ...). */
export class MekoConnectionError extends MekoError {}

/** Meko was reached but a tool call failed or returned an error-shaped payload. */
export class MekoToolError extends MekoError {
  constructor(message, { tool, payload, options } = {}) {
    super(message, options);
    this.tool = tool;
    this.payload = payload;
  }
}

/** Attempt to violate the trust model (e.g. VERIFIED without verification evidence). */
export class TrustViolationError extends TrustTraceError {}
