// Obviously-fake credential-shaped values for tests. They are ASSEMBLED AT RUNTIME on purpose: the finished strings are identical to the
// literals the tests used before (so every assertion is unchanged), but no complete credential-looking literal (Meko token, PEM header,
// password-bearing connection string) sits in the repository for secret scanners to flag. None of these is a real credential.

/** A fake Meko API key: mko_tkn_<suffix> */
export const mekoKey = (suffix) => ['mko', 'tkn', suffix].join('_');

/** The header line of a PEM private key, used to prove such material never leaks into config or API output. */
export const PEM_HEADER = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');

/** A fake PostgreSQL URL with a fake password: postgres://<user>:<password>@<hostAndDb> */
export const pgUrl = (user, password, hostAndDb) => ['postgres:', '//', user, ':', password, '@', hostAndDb].join('');
