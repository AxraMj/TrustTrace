// Agent A's language extraction (deterministic, no LLM).
//
// Replaces the Phase 1-3 single-regex rules with a small concept matcher:
//   * sentence split, contraction/typo normalisation, light stemming (applied to text AND lexicon, so inflections match)
//   * each claim is a CONCEPT PAIR found within a short token window of one sentence
//       e.g. lost_device_claim = a DEVICE word near a LOSS/DAMAGE word (either order), or "got a new <device>"
//            request_mfa_reset  = an MFA term near a RESET/REMOVE/MOVE verb (either order)
//   * negation ("not a director", "nothing urgent"), third-person/informational sentences ("what is 2FA?",
//     "training about password resets") and light typo tolerance (edit distance 1 for longer words)
// Limits (honest): English only; needs sensible punctuation/capitalisation for names; no coreference; no
// understanding of sarcasm or multi-sentence context; synonyms outside the lexicons are missed.
// Every claim extracted here is only a CLAIMED/OBSERVED signal - never trusted evidence.

// ---------------------------------------------------------------- normalisation & stemming
export function stem(word) {
  let s = word;
  if (s.endsWith('ies') && s.length > 4) s = s.slice(0, -3) + 'y';
  else if (s.endsWith('ing') && s.length > 5) s = s.slice(0, -3);
  else if (s.endsWith('ed') && s.length > 4) s = s.slice(0, -2);
  else if (s.endsWith('es') && s.length > 4) s = s.slice(0, -2);
  else if (s.endsWith('s') && !s.endsWith('ss') && s.length > 3) s = s.slice(0, -1);
  if (s.length > 3 && s[s.length - 1] === s[s.length - 2]) s = s.slice(0, -1); // resett -> reset
  if (s.endsWith('e') && s.length > 3) s = s.slice(0, -1); // wipe/wiped -> wip
  return s;
}

const CONTRACTIONS = [
  [/\bcan['’]?t\b/g, 'cannot'], [/\bwon['’]?t\b/g, 'will not'], [/\bdon['’]?t\b/g, 'do not'], [/\bdoesn['’]?t\b/g, 'does not'],
  [/\bdidn['’]?t\b/g, 'did not'], [/\bisn['’]?t\b/g, 'is not'], [/\baren['’]?t\b/g, 'are not'], [/\bwasn['’]?t\b/g, 'was not'],
  [/\bhaven['’]?t\b/g, 'have not'], [/\bhasn['’]?t\b/g, 'has not'], [/\bwouldn['’]?t\b/g, 'would not'], [/\bcouldn['’]?t\b/g, 'could not'],
  [/\bi['’]m\b/g, 'i am'], [/\bim\b/g, 'i am'], [/\bi['’]ve\b/g, 'i have'], [/\bi['’]d\b/g, 'i would'], [/\bi['’]ll\b/g, 'i will'],
  [/\bit['’]s\b/g, 'it is'], [/\bthat['’]s\b/g, 'that is'], [/\blet['’]s\b/g, 'let us'], [/\bpls\b|\bplz\b/g, 'please'], [/\bmi\b/g, 'my'],
  [/n['’]t\b/g, ' not'],
];
function normalise(sentence) {
  let s = sentence.toLowerCase();
  for (const [re, rep] of CONTRACTIONS) s = s.replace(re, rep);
  s = s.replace(/['’]s\b/g, 's').replace(/['’]/g, '').replace(/[-_/]/g, ' ');
  return s;
}
const tokenise = (s) => s.split(/[^a-z0-9]+/).filter(Boolean);

function lev1(a, b) {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) return a.slice(i + 1) === b.slice(i + 1) || (a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2));
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : b.slice(i + 1) === a.slice(i);
}
const same = (a, b) => a === b || (a.length >= 7 && b.length >= 7 && lev1(a, b)); // typo tolerance only for longer words

const MAX_MATCHES = 200;
const L = (phrases) => phrases.map((p) => p.split(' ').map((w) => stem(w))); // lexicon: stem every word
function find(stems, phrases) {
  const out = [];
  for (const ph of phrases) {
    for (let i = 0; i + ph.length <= stems.length; i++) {
      let ok = true;
      for (let j = 0; j < ph.length && ok; j++) ok = same(stems[i + j], ph[j]);
      if (ok) out.push({ start: i, end: i + ph.length - 1, len: ph.length });
      if (out.length >= MAX_MATCHES) return out; // bound the pairwise window search on pathological input
    }
  }
  return out;
}
function gap(a, b) {
  if (b.start > a.end) return b.start - a.end - 1;
  if (a.start > b.end) return a.start - b.end - 1;
  return -1; // overlap
}
const near = (A, B, max) => A.some((a) => B.some((b) => { const g = gap(a, b); return g >= 0 && g <= max; }));
const nearPair = (A, B, max) => { for (const a of A) for (const b of B) { const g = gap(a, b); if (g >= 0 && g <= max) return [a, b]; } return null; };
const NEG = new Set(['not', 'no', 'never', 'nothing', 'without', 'cannot', 'unable', 'neither', 'nobody'].map(stem));
const negatedBefore = (stems, pos, win = 3) => stems.slice(Math.max(0, pos.start - win), pos.start).some((t) => NEG.has(t));
// A verb is negated only when the negation DIRECTLY governs it ("do not get", "never receive", "not able to see",
// "no longer receive"), not merely when a negation appears a few words earlier in an unrelated idiom.
const NEG_FILLER = new Set(['able', 'to', 'ever', 'really', 'even', 'longer', 'seem', 'can', 'could', 'be', 'any', 'more'].map(stem));
const URG_FILLER = new Set(['in', 'a', 'an', 'the', 'really', 'that', 'very', 'so', 'too', 'at', 'all', 'particularly', 'especially', 'any', 'exactly', 'of', 'much', 'overly', 'is', 'be'].map(stem));
function negates(stems, pos, fillers) {
  for (let i = pos.start - 1, hops = 0; i >= 0 && hops < 4; i--, hops++) {
    if (NEG.has(stems[i])) return true;
    if (!fillers.has(stems[i])) return false; // an unrelated word in between: the negation belongs to something else
  }
  return false;
}
const negatedAvail = (stems, pos) => negates(stems, pos, NEG_FILLER);
// "a hung-up phone" style false friends: a dead BATTERY is not a lost device.
const batteryNear = (stems, l) => stems.slice(Math.max(0, l.start - 3), l.end + 4).includes('battery');
// Account-lockout that is about an account/system (not "locked out of the printer").
const LOCKED_OUT_RE = /\block(?:ed)? out(?: of (?:my |the |our |this )?(?:account|login|system|email|e mail|portal|network|vpn|computer|laptop|everything|apps?|profile|machine|workstation|phone|payroll|work)|(?= and| because| so| again| after| now)|\s*[.,!?]|$)/;
const OWN_DEST_RE = /\b(?:forward|forwarded|forwarding|redirect|redirected|reroute|rerouted|route|routed)\b[^.!?]{0,40}\b(?:to|onto) my (?:own )?(?:email|e mail|mobile|phone|number|inbox|address)\b/;

// ---------------------------------------------------------------- lexicons
const DEVICE = L(['phone', 'handset', 'mobile', 'cell', 'cellphone', 'smartphone', 'iphone', 'android', 'device', 'laptop', 'tablet', 'sim', 'sim card', 'handheld', 'token', 'security key', 'fob']);
const LOSS = L(['lost', 'lose', 'misplaced', 'stolen', 'stole', 'steal', 'nicked', 'swiped', 'pinched', 'snatched', 'pickpocketed', 'robbed', 'mugged',
  'broke', 'broken', 'smashed', 'cracked', 'crushed', 'drowned', 'fell in', 'fell into', 'dropped in', 'dropped into', 'water damage', 'damaged', 'destroyed',
  'fried', 'dead', 'died', 'gone', 'missing', 'left behind', 'stopped working', 'no longer works', 'will not turn on', 'not turn on', 'shattered', 'shatter', 'left on', 'left in', 'fell off', 'spilled']);
// "got a (brand) new <device>": adjective directly before a DEVICE word (plus 'new number'), after an acquisition verb.
const NEW_ADJ = L(['new', 'replacement', 'different', 'borrowed', 'temporary', 'spare', 'upgraded']);
const NEW_NUMBER = L(['new number']);
const ACQUIRE = L(['got', 'get', 'bought', 'buy', 'have', 'using', 'use', 'switched', 'moved', 'upgraded', 'changed', 'replaced', 'received', 'purchased', 'ordered', 'picked up', 'swapped', 'now on']);

const MFA = L(['mfa', '2fa', 'two factor', 'second factor', '2nd factor', 'two step', 'second step', '2 step', 'multi factor', 'multifactor', 'authenticator',
  'authentication app', 'auth app', 'verification code', 'security code', 'login code', 'sign in code', 'one time code', 'one time passcode', 'one time password',
  'otp', 'sms code', 'text code', 'verification text', 'security step', 'extra security', 'additional security', 'security token', 'passkey', 'login approval',
  'verification method', 'push notification', 'two step verification', 'authentication method', 'layer of security', 'extra layer', 'second layer', 'security layer']);
const CODES = L(['code', 'passcode', 'otp', 'sms', 'text message', 'verification text', 'verification message', 'text', 'sign in request', 'login request', 'approval request', 'push request']);
const MFA_ACTION = L(['reset', 'wipe', 'remove', 'disable', 'delete', 'clear', 'deactivate', 'bypass', 'unenrol', 'unenroll', 'un enrol', 're enrol', 're enroll',
  're register', 're pair', 'reassign', 'move', 'transfer', 'switch', 'swap', 'replace', 'change', 'attach', 'link', 'relink', 'drop', 'strip', 'detach', 'unlink', 'turn off', 'switch off', 'take off', 'taken off']);
const OFF_VERBS = L(['turn', 'switch', 'take', 'taken', 'get', 'knock', 'strip', 'pull', 'put', 'move']);
const NOT_WORKING = L(['not working', 'does not work', 'do not work', 'stopped working', 'broken', 'dead', 'gone', 'missing', 'lost', 'disappeared', 'deleted', 'wiped', 'fails', 'not open', 'not load']);
const AVAIL = L(['get', 'receive', 'see', 'access', 'read', 'use', 'find', 'open', 'arrive', 'come', 'work', 'show', 'appear', 'load', 'generate', 'approve', 'accept', 'confirm', 'authorise', 'authorize']);

const PW_STRONG = L(['password', 'passphrase', 'credential', 'login detail', 'log in detail', 'sign in detail', 'pin']);
const PW_WEAK = L(['login', 'log in', 'sign in', 'account', 'access']);
const PW_ACTION = L(['reset', 'change', 'forgot', 'forget', 'forgotten', 'recover', 'restore', 'unlock', 'generate', 'issue', 'send', 'set', 'create', 'give', 'replace', 'retrieve', 'reissue', 'regain', 'refresh']);
const PW_ADJ = L(['new', 'temporary', 'fresh', 'replacement', 'different']); // only counts when directly adjacent ("a new password")
const FORGOT = L(['forgot', 'forget', 'forgotten']);
const CRED_NOUN = L(['login', 'log in', 'sign in', 'account', 'credential', 'password', 'passphrase', 'pin', 'detail']);
const PW_STRICT_ACTION = L(['reset', 'unlock', 'recover', 'restore', 'regain', 'reissue', 'retrieve']);
// ("locked out" itself is handled by LOCKED_OUT_RE below: it only counts when the object is an account/system)
const LOCKOUT = L(['cannot log in', 'cannot login', 'cannot sign in', 'cannot get in', 'cannot access my account', 'cannot get into', 'need back in', 'get back in',
  'back into my account', 'unable to log in', 'cannot log on', 'forgot my password', 'forgotten my password']);
const RESET = L(['reset']);
const LINKISH = L(['link', 'email', 'code', 'message']);
const ARRIVE = L(['arrive', 'come', 'receive', 'get', 'show', 'appear']);
const REQUEST_VERB = L(['send', 'give', 'issue', 'do', 'need', 'want', 'request', 'trigger', 'get', 'please', 'could', 'can', 'would', 'will', 'like', 'run', 'start']);

const CONTACT_NOUN = L(['phone number', 'mobile number', 'cell number', 'contact number', 'number on file', 'email', 'e mail', 'email address', 'recovery email', 'recovery phone',
  'recovery number', 'recovery detail', 'contact detail', 'contact info', 'contact information']);
const CONTACT_ACTION = L(['change', 'update', 'add', 'replace', 'swap', 'edit', 'set', 'switch', 'alter', 'amend', 'correct', 'register']);
const REDIRECT = L(['send', 'sent', 'forward', 'redirect', 'route', 'deliver', 'move', 'attach', 'link', 'point', 'switch', 'transfer', 'text', 'email']);
const DEST_RE = /\b(?:(?:my |a |an |the )?(?:new|another|different|other|alternate|alternative|personal|private|temporary) (?:number|email|e mail|address|phone|mobile|inbox)|somewhere else|elsewhere|(?:wife|husband|partner|friend|colleague|assistant|brother|sister|mother|father|son|daughter|spouse)s? (?:number|phone|email|mobile))\b/;
const CODEISH = L(['code', 'link', 'notification', 'text', 'message', 'approval', 'reset', 'passcode', 'otp', 'sms', 'second factor', 'second step', 'authenticator', 'mfa', '2fa', 'verification']);

// STRONG nouns identify banking on their own; WEAK payroll words only count together with an account/bank destination,
// so "update the team calendar with the payroll cut-off date" is not a bank-detail request.
const BANK_NOUN = L(['bank account', 'bank detail', 'banking detail', 'bank', 'direct deposit', 'deposit account', 'iban', 'swift', 'routing number', 'sort code', 'account number',
  'payment detail', 'payment account']);
const BANK_WEAK = L(['payroll', 'salary', 'paycheck', 'paycheque', 'wage', 'reimbursement', 'expense', 'my pay', 'pay']);
const BANK_ACTION = L(['change', 'update', 'switch', 'move', 'redirect', 'route', 'send', 'swap', 'alter', 'amend', 'replace', 'edit', 'correct', 'set up', 'add', 'wire',
  'transfer', 'direct', 'read out', 'paid', 'pay', 'deposit', 'put']);
const PAY_NOUN = L(['wage', 'salary', 'pay', 'paycheck', 'paycheque', 'payroll', 'reimbursement', 'expense', 'bonus', 'commission']);
const ACCOUNT_DEST = L(['account', 'iban', 'bank', 'new account', 'different account']);

const TITLE = L(['cfo', 'ceo', 'cto', 'coo', 'cio', 'ciso', 'cmo', 'chief', 'president', 'vp', 'svp', 'evp', 'vice president', 'director', 'executive', 'exec', 'partner',
  'chairman', 'chairwoman', 'chair', 'owner', 'founder', 'principal', 'manager', 'supervisor', 'treasurer', 'controller', 'contractor', 'consultant', 'administrator', 'admin',
  'sysadmin', 'team lead', 'head of', 'board member', 'general manager', 'managing director', 'general counsel']);
const ROLE_LEAD = L(['i am', 'this is', 'it is', 'as', 'speaking as', 'calling as', 'on behalf of', 'i work as', 'i act as', 'speaking with the', 'am']);
const FILLER = new Set(L(['a', 'an', 'the', 'one', 'of', 'your', 'our', 'its', 'my', 'senior', 'junior', 'deputy', 'acting', 'new', 'regional', 'global', 'group', 'managing',
  'assistant', 'associate', 'interim', 'vice', 'incoming', 'only', 'also', 'just', 'actually', 'currently', 'still', 'really', 'proud', 'executive']).flat());
const DEPT = L(['finance', 'payroll', 'accounts', 'accounting', 'treasury', 'hr', 'human resources', 'it department', 'it support', 'it team', 'security team', 'legal', 'procurement', 'sales',
  'operations', 'audit', 'compliance', 'head office']);
const DEPT_LEAD = L(['from', 'in', 'with', 'at', 'within']);
const LEAD_VERBS = L(['head', 'run', 'lead', 'manage', 'oversee', 'own', 'chair']);
const UNIT_NOUN = L(['team', 'department', 'division', 'group', 'business', 'company', 'firm', 'office', 'function', 'unit', 'treasury', 'finance', 'payroll', 'sales', 'operations', 'hr']);
// "our CFO asked me to ...": the title must be followed (allowing aux/adverbs) by a request verb AND "me/us".
const ON_BEHALF_VERB = new Set(['asked', 'told', 'sent', 'wants', 'needs', 'requested', 'instructed', 'authorised', 'authorized', 'tasked']);
const ON_BEHALF_AUX = new Set(['has', 'had', 'just', 'also', 'then', 'now', 'already', 'really', 'only', 'kindly']);
const IDENTITY_CONTEXT = L(['i am', 'this is', 'it is', 'here', 'speaking', 'calling', 'my name', 'we']);

const URGENT = L(['urgent', 'urgently', 'urgency', 'asap', 'immediately', 'immediate', 'right now', 'right away', 'straight away', 'at once', 'as soon as possible',
  'as quickly as possible', 'hurry', 'hurry up', 'rush', 'emergency', 'time sensitive', 'time critical', 'deadline', 'cannot wait', 'cannot hang around',
  'cannot wait around', 'no time', 'running out of time', 'within the hour', 'speed this up', 'speed up', 'not got all day', 'not have all day', 'critical', 'right this minute', 'this minute']);
// RAW words (unstemmed): "pressing" (urgent) must not match "the press" (same stem); "quickly" only as a demand, not praise ("how quickly you fixed it").
const URGENT_NEED_RE = /\b(?:need|want|must|have to|got to|please|get|do|fix|sort|handle|resolve|done)\b[^.!?]*\bquickly\b|\bquickly,? (?:please|now)\b/;
const TIME_RE = /\b(?:in|within) (?:a few|a couple of|couple of|the next|the next few|one|two|three|four|five|ten|fifteen|twenty|thirty|\d+) ?(?:more )?(?:minute|min|hour|second)s?\b/;
const BOSS = L(['boss', 'manager', 'supervisor', 'ceo', 'cfo', 'director', 'chairman', 'chair', 'president', 'board', 'management', 'executive', 'leadership', 'vp', 'head of department']);
// Raw (unstemmed) so that "asking" (pressure) is not confused with "asked" (a plain request): they share a stem.
const BOSS_WAIT_RAW = new Set(['waiting', 'expecting', 'asking', 'chasing', 'demanding', 'hounding', 'pestering', 'insisting']);
const ANGRY = L(['ballistic', 'furious', 'livid', 'angry', 'upset', 'annoyed', 'mad', 'hit the roof', 'blow up', 'unhappy', 'not happy', 'fired', 'sacked', 'disciplinary', 'lose it', 'go nuts']);
const THREAT = L(['get you fired', 'have you fired', 'lose your job', 'report you', 'complain', 'escalate', 'call your manager', 'speak to your manager', 'talk to your supervisor',
  'your supervisor', 'your manager', 'your boss', 'go to your boss', 'take this further', 'raise this with', 'make a complaint', 'calling your manager',
  'go to the press', 'go public', 'the media', 'legal action', 'my lawyer', 'my solicitor', 'sue you']);

const SKIP = L(['skip', 'bypass', 'waive', 'avoid', 'ignore', 'forget', 'drop', 'skip over', 'dispense with', 'get around', 'do without', 'go without', 'not bother with', 'no need for',
  'do not need', 'not necessary', 'without', 'rather not', 'prefer not', 'would rather not', 'do not bother', 'not going through', 'not go through', 'skip past',
  'no need to', 'cannot be bothered with']);
const CHECK = L(['verification', 'verify', 'security question', 'question', 'check', 'callback', 'call back', 'id check', 'identity', 'process', 'procedure', 'protocol', 'formality',
  'authentication', 'security step', 'security check', 'confirmation', 'confirm', 'proof', 'usual']);
const REFUSE = L(['will not', 'refuse', 'do not', 'am not going to', 'not going to', 'not about to', 'cannot be bothered']);
const ANSWER = L(['answer', 'provide', 'give', 'go through', 'do', 'submit']);
const NO_CALLBACK_RE = /\b(?:do not|no need to|never|there is no need to|dont|do not even) (?:bother )?(?:call|calling|phone|phoning|ring|ringing|contact|contacting) (?:me )?back\b/;

// RAW words, not stems: the stem of "training" is "train", which must not suppress "I lost my mobile on the train".
const INFORMATIONAL_RAW = new Set(['awareness', 'training', 'trainings', 'policy', 'policies', 'webinar', 'tutorial', 'documentation', 'explain', 'explanation', 'article', 'newsletter',
  'presentation', 'session', 'sessions', 'workshop']);
const INFO_START = /^(?:what|how|why|when|where|which|who) (?:is|are|does|do|can|should|would|did)\b|^(?:can|could) you (?:explain|tell me)/;

// ---------------------------------------------------------------- names (case-sensitive)
const CAP = "[A-Z][a-z]+(?:['’-][A-Za-z]+)*";
const NAME_TOKENS = `(?:(?:Mr|Mrs|Ms|Dr|Prof)\\.?\\s+)?${CAP}(?:\\s+${CAP}){0,2}`;
const STOP_NAMES = new Set(['I', 'Hi', 'Hello', 'Hey', 'Good', 'Morning', 'Afternoon', 'Evening', 'Thanks', 'Thank', 'Please', 'Sorry', 'Yes', 'No', 'Okay', 'Ok', 'Well', 'So', 'It', 'The', 'A', 'An',
  'My', 'We', 'Our', 'Can', 'Could', 'Would', 'Will', 'Is', 'Are', 'Do', 'Does', 'Dear', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday', 'January',
  'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December', 'Urgent', 'Important', 'Right', 'Speaking', 'Calling', 'Here', 'This', 'That']);
function cleanName(raw) {
  const toks = raw.replace(/\.$/, '').split(/\s+/).filter((t) => !STOP_NAMES.has(t.replace(/\.$/, '')));
  return toks.length ? toks.join(' ') : null;
}
function findName(text) {
  const lead = /\b(?:this is|it is|it['’]s|i am|i['’]m|my name is|my name['’]s|name['’]s|speaking with|you are speaking (?:to|with)|you['’]re speaking (?:to|with)|calling for)\s+/gi;
  let m;
  while ((m = lead.exec(text))) {
    const rest = text.slice(m.index + m[0].length);
    const nm = new RegExp(`^(${NAME_TOKENS})`).exec(rest);
    const cleaned = nm && cleanName(nm[1]);
    if (cleaned) return cleaned;
  }
  const after = new RegExp(`\\b(${NAME_TOKENS})\\s+(?:here|speaking|calling)\\b`, 'g');
  while ((m = after.exec(text))) {
    const cleaned = cleanName(m[1]);
    if (cleaned) return cleaned;
  }
  return null;
}

// ---------------------------------------------------------------- per-sentence detectors
const upper = (stems) => stems.join(' ').toUpperCase();

function analyseSentence(raw, call) {
  const norm = normalise(raw);
  const toks = tokenise(norm);
  const st = toks.map(stem);
  const info = INFO_START.test(norm.trim()) || toks.some((t) => INFORMATIONAL_RAW.has(t));
  const hits = {};
  const set = (kind, statement) => { hits[kind] ??= statement; };

  // ---- role claims
  {
    const leads = find(st, ROLE_LEAD);
    const titles = find(st, TITLE);
    for (const t of titles) {
      for (const l of leads) {
        if (l.end < t.start && t.start - l.end - 1 <= 5) {
          const between = st.slice(l.end + 1, t.start);
          if (between.every((w) => FILLER.has(w)) && !negatedBefore(st, l, 3) && !between.some((w) => NEG.has(w))) {
            set('role_claim', `Caller claims the role of ${toks.slice(t.start, t.end + 1).join(' ').toUpperCase()}.`);
          }
        }
      }
      // "our CFO asked me to call": acting on behalf of an executive. Uses RAW tokens (not stems): "asked"/"asking"
      // share a stem, and "the director's office asked me to confirm the printer" must NOT match.
      let k = t.end + 1;
      while (k < toks.length && ON_BEHALF_AUX.has(toks[k])) k++;
      if (ON_BEHALF_VERB.has(toks[k]) && ['me', 'us'].includes(toks[k + 1]) && st.slice(Math.max(0, t.start - 2), t.start).some((w) => ['our', 'my', 'the'].includes(w)) && !negatedBefore(st, t, 3)) {
        set('role_claim', `Caller claims to act on behalf of the ${toks.slice(t.start, t.end + 1).join(' ').toUpperCase()}.`);
      }
    }
    // "I head up the treasury team"
    for (const v of find(st, LEAD_VERBS)) {
      if (st[v.start - 1] === 'i' || st[v.start - 2] === 'i') {
        const units = find(st, UNIT_NOUN);
        if (units.some((u) => u.start > v.end && u.start - v.end - 1 <= 4) && !negatedBefore(st, v, 2)) set('role_claim', 'Caller claims to lead a team/department.');
      }
    }
    // "from the payroll office" / "I'm in HR" (affiliation claim)
    if (!hits.role_claim) {
      const idCtx = find(st, IDENTITY_CONTEXT).length > 0 || call.hasName;
      for (const d of find(st, DEPT)) {
        const lead = find(st.slice(Math.max(0, d.start - 3), d.start), DEPT_LEAD);
        if (idCtx && lead.length && !negatedBefore(st, d, 4)) set('role_claim', `Caller claims to work in ${toks.slice(d.start, d.end + 1).join(' ')}.`);
      }
    }
  }

  // ---- lost / replaced device
  if (!info) {
    const dev = find(st, DEVICE);
    const loss = find(st, LOSS).filter((l) => !(l.len === 1 && negatedBefore(st, l, 2)) && !batteryNear(st, l));
    const LOST = 'Caller claims their phone/device was lost, stolen or replaced.';
    if (near(dev, loss, 6)) set('lost_device_claim', LOST);
    const acquired = (pos) => st.slice(Math.max(0, pos.start - 5), pos.start).some((w) => ACQUIRE.some((a) => a[0] === w));
    // "got a (brand) new iPhone": a replacement adjective directly before a device word, after an acquisition verb
    for (const d of dev) for (const a of find(st, NEW_ADJ)) {
      const g = d.start - a.end - 1;
      if (g >= 0 && g <= 1 && acquired(a)) set('lost_device_claim', LOST);
    }
    for (const nn of find(st, NEW_NUMBER)) if (acquired(nn)) set('lost_device_claim', LOST);
  }

  // ---- MFA unavailable
  {
    const mfa = find(st, MFA);
    const codes = find(st, CODES);
    const target = [...mfa, ...codes];
    for (const a of find(st, AVAIL)) {
      if (negatedAvail(st, a) && near([a], target, 3) && !info) set('mfa_unavailable_claim', 'Caller claims they cannot receive or use their MFA code.');
    }
    if (near(mfa, NOT_WORKING, 5) && !negatedBefore(st, mfa[0] ?? { start: 0 }, 2) && !info) set('mfa_unavailable_claim', 'Caller claims they cannot receive or use their MFA code.');
    if (/\blocked out of (?:my |the )?(?:authenticator|mfa|2fa)/.test(norm)) set('mfa_unavailable_claim', 'Caller claims they cannot receive or use their MFA code.');
  }

  // ---- requests
  if (!info) {
    const mfa = find(st, MFA);
    const act = find(st, MFA_ACTION).filter((a) => !negatedBefore(st, a, 2) || true);
    if (near(mfa, act, 7)) set('request_mfa_reset', 'Caller requests an MFA reset/change.');
    const offs = find(st, L(['off']));
    if (mfa.length && offs.some((o) => near([o], mfa, 5)) && find(st.slice(0, offs[0].start), OFF_VERBS).length) set('request_mfa_reset', 'Caller requests an MFA reset/change.');

    // password
    const strong = find(st, PW_STRONG), weak = find(st, PW_WEAK), pa = find(st, PW_ACTION), pas = find(st, PW_STRICT_ACTION);
    if (near(strong, pa, 6) || near(weak, pas, 5)) set('request_password_reset', 'Caller requests a password reset.');
    // "a new password" (adjective DIRECTLY before the noun; "a stronger password for the new year" is not a request)
    for (const s of strong) if (find(st.slice(Math.max(0, s.start - 2), s.start), PW_ADJ).length) set('request_password_reset', 'Caller requests a password reset.');
    // "I forgot my login / account details"
    if (near(find(st, FORGOT), find(st, CRED_NOUN), 3)) set('request_password_reset', 'Caller requests a password reset.');
    const resets = find(st, RESET);
    if (resets.length && find(st, LINKISH).some((l) => near([l], resets, 2)) && st.some((w) => NEG.has(w)) && find(st, ARRIVE).length) set('request_password_reset', 'Caller requests a password reset.');
    const asksFor = (r) => st.slice(Math.max(0, r.start - 4), r.start).some((w) => REQUEST_VERB.some((q) => q[0] === w));
    if (resets.length && !mfa.length && (call.lockout || call.passwordNoun) && resets.some(asksFor)) {
      set('request_password_reset', 'Caller requests a password reset.');
    }
    // NOUN use of "reset" ("send me a reset") in an account-lockout context is a password-reset request even when an MFA
    // request shares the sentence; the VERB use ("reset my authenticator") belongs to the MFA request instead.
    const nounResets = resets.filter((r) => ['a', 'the', 'another', 'one'].includes(st[r.start - 1]));
    if (nounResets.some(asksFor) && (call.lockout || call.passwordNoun)) set('request_password_reset', 'Caller requests a password reset.');

    // contact details
    const cn = find(st, CONTACT_NOUN), ca = find(st, CONTACT_ACTION);
    if (near(cn, ca, 6)) set('request_contact_change', 'Caller requests a change to phone/email/recovery details.');
    if (DEST_RE.test(norm) && find(st, REDIRECT).length && find(st, CODEISH).length) set('request_contact_change', 'Caller requests a change to phone/email/recovery details.');
    if (OWN_DEST_RE.test(norm) && find(st, CODEISH).length) set('request_contact_change', 'Caller requests a change to phone/email/recovery details.');

    // bank / payroll: strong nouns alone; weak payroll words only together with an account/bank destination
    const bn = find(st, BANK_NOUN).filter((b) => !(toks[b.start] === 'bank' && ['holiday', 'statement', 'holidays'].includes(toks[b.end + 1])));
    const bw = find(st, BANK_WEAK);
    const ba = find(st, BANK_ACTION);
    const dest = find(st, ACCOUNT_DEST);
    if (near(bn, ba, 8)) set('request_bank_detail_change', 'Caller requests a change to payroll/bank details.');
    if (bw.length && ba.length && near(bw, ba, 8) && (dest.length || bn.length)) set('request_bank_detail_change', 'Caller requests a change to payroll/bank details.');
  }

  // ---- pressure / behaviour (observed)
  {
    // Phrases that are themselves negated idioms ("cannot wait", "not got all day") skip the negation filter.
    // Negation must DIRECTLY govern the urgency word ("nothing urgent", "no rush", "not in a hurry"); "if you cannot
    // help me right now" is not a negated urgency.
    const urg = find(st, URGENT).filter((u) => NEG.has(st[u.start]) || !negates(st, u, URG_FILLER));
    if (urg.length || TIME_RE.test(norm) || toks.includes('pressing') || URGENT_NEED_RE.test(norm)) set('urgency_pressure', 'Caller applied urgency/time pressure.');
    const boss = find(st, BOSS);
    const waitPos = toks.map((w, i) => (BOSS_WAIT_RAW.has(w) ? { start: i, end: i } : null)).filter(Boolean);
    if (boss.some((b) => near([b], waitPos, 4)) || (boss.length && find(st, ANGRY).length) || find(st, THREAT).length) {
      set('authority_pressure', 'Caller invoked authority or threatened consequences.');
    }
    const skip = find(st, SKIP), chk = find(st, CHECK);
    if ((near(skip, chk, 6) && !info) || NO_CALLBACK_RE.test(norm)) set('verification_resistance', 'Caller resisted or tried to skip verification.');
    // "I refuse to answer your questions" / "I won't be answering your security questions" - but NOT
    // "I don't know the answer to your question" (inability, not refusal): know/remember/recall between them rules it out.
    const CANNOT_RECALL = new Set(['know', 'remember', 'recall', 'sure', 'have', 'got']);
    const answers = find(st, ANSWER);
    const refusal = find(st, REFUSE).some((r) => answers.some((a) => a.start > r.end && a.start - r.end - 1 <= 3 && !st.slice(r.end + 1, a.start).some((w) => CANNOT_RECALL.has(w))));
    if (refusal && near(answers, find(st, L(['security question', 'question', 'verification', 'check', 'process'])), 4)) {
      set('verification_resistance', 'Caller resisted or tried to skip verification.');
    }
  }
  return hits;
}

/** Extract claim/observation facts from a call transcript. One fact per kind, claims first. */
export function extractFacts(text) {
  const raw = String(text ?? '');
  const sentences = raw.split(/(?<=[.!?;])\s+|\n+/).map((s) => s.trim()).filter(Boolean);
  const allStems = tokenise(normalise(raw)).map(stem);
  const name = findName(raw);
  const call = {
    hasName: Boolean(name),
    lockout: find(allStems, LOCKOUT).length > 0 || LOCKED_OUT_RE.test(normalise(raw)),
    passwordNoun: find(allStems, PW_STRONG).length > 0,
  };
  const hits = {};
  for (const s of sentences) {
    for (const [k, v] of Object.entries(analyseSentence(s, call))) hits[k] ??= v;
    // appositive introduction: "Dr. Ingrid Solheim, medical director - I need ..."
    const app = new RegExp(`^(${NAME_TOKENS})\\s*[,—–-]+\\s*([^.!?]{0,40})`).exec(s);
    const appName = app && cleanName(app[1]);
    if (appName && !STOP_NAMES.has(app[1].trim())) {
      const title = find(tokenise(normalise(app[2])).map(stem), TITLE);
      if (title.length) {
        hits.identity_claim ??= `Caller claims to be ${appName}.`;
        hits.role_claim ??= `Caller claims the role of ${tokenise(normalise(app[2])).slice(title[0].start, title[0].end + 1).join(' ').toUpperCase()}.`;
      }
    }
  }
  if (name) hits.identity_claim = `Caller claims to be ${name}.`;

  const CLAIMS = ['identity_claim', 'role_claim', 'lost_device_claim', 'mfa_unavailable_claim', 'request_mfa_reset', 'request_password_reset', 'request_contact_change', 'request_bank_detail_change'];
  const OBSERVED = ['urgency_pressure', 'authority_pressure', 'verification_resistance'];
  return [
    ...CLAIMS.filter((k) => hits[k]).map((kind) => ({ label: 'CLAIMED', kind, statement: hits[kind] })),
    ...OBSERVED.filter((k) => hits[k]).map((kind) => ({ label: 'OBSERVED', kind, statement: hits[kind] })),
  ];
}
