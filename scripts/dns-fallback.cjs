// OPERATOR-ONLY preload for LOCAL runs:  node --require ./scripts/dns-fallback.cjs --env-file=.env.demo <script>
// Not used by the deployed service and never loaded by the application.
//
// Problem it works around: on some networks the router's DNS answers REFUSED for Neon endpoint names, so Node's system lookup (getaddrinfo)
// fails with ENOTFOUND even though 1.1.1.1 resolves them.
// Behaviour: the normal system lookup runs first and is used whenever it works. ONLY if it fails for a host ending in ".neon.tech" is the same
// name resolved through 1.1.1.1. Every other host is untouched. TLS verification is unchanged: the certificate is still checked against the
// hostname, whichever resolver supplied the address.
const dns = require('node:dns');

const original = dns.lookup;
const resolver = new dns.Resolver();
resolver.setServers(['1.1.1.1']);

dns.lookup = function lookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof options === 'number') options = { family: options };
  options = options ?? {};
  return original.call(dns, hostname, options, (err, address, family) => {
    if (!err || typeof hostname !== 'string' || !/\.neon\.tech$/i.test(hostname)) return callback(err, address, family);
    resolver.resolve4(hostname, (err2, addresses) => {
      if (err2 || !addresses || addresses.length === 0) return callback(err);
      if (options.all) return callback(null, addresses.map((a) => ({ address: a, family: 4 })));
      return callback(null, addresses[0], 4);
    });
  });
};
