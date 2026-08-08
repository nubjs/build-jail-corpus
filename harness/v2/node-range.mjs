const parseVersion = (value, { partial = false } = {}) => {
  const match = /^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:[-+].*)?$/.exec(String(value).trim());
  if (!match) return null;
  const parts = match.slice(1).map((part) => part == null || /^[xX*]$/.test(part) ? null : Number(part));
  if (!partial && parts.some((part) => part == null)) return null;
  return parts;
};

const compare = (a, b) => {
  for (let i = 0; i < 3; i++) {
    const delta = a[i] - b[i];
    if (delta) return Math.sign(delta);
  }
  return 0;
};

const lower = (parts) => parts.map((part) => part ?? 0);

const upperForPartial = (parts) => {
  if (parts[0] == null) return null;
  if (parts[1] == null) return [parts[0] + 1, 0, 0];
  if (parts[2] == null) return [parts[0], parts[1] + 1, 0];
  return null;
};

const comparator = (op, expected) => (actual) => {
  const order = compare(actual, expected);
  return op === '>' ? order > 0 : op === '>=' ? order >= 0
    : op === '<' ? order < 0 : op === '<=' ? order <= 0 : order === 0;
};

const expandToken = (token) => {
  if (!token || token === '*' || /^[xX]$/.test(token)) return [];
  const match = /^(\^|~|>=|<=|>|<|=)?\s*(.+)$/.exec(token);
  if (!match) return null;
  const [, op = '', raw] = match;
  const parts = parseVersion(raw, { partial: true });
  if (!parts) return null;
  const floor = lower(parts);
  if (op === '^') {
    const upper = parts[0] > 0 ? [parts[0] + 1, 0, 0]
      : parts[1] > 0 ? [0, parts[1] + 1, 0] : [0, 0, (parts[2] ?? 0) + 1];
    return [comparator('>=', floor), comparator('<', upper)];
  }
  if (op === '~') {
    const upper = parts[1] == null ? [parts[0] + 1, 0, 0] : [parts[0], parts[1] + 1, 0];
    return [comparator('>=', floor), comparator('<', upper)];
  }
  const upper = upperForPartial(parts);
  if (op === '>' && upper) return [comparator('>=', upper)];
  if (op === '<=' && upper) return [comparator('<', upper)];
  if (op === '<' || op === '>=' || op === '>' || op === '<=') return [comparator(op, floor)];
  if (op === '=' || !op) {
    return upper ? [comparator('>=', floor), comparator('<', upper)] : [comparator('=', floor)];
  }
  return null;
};

const predicatesForSet = (set) => {
  const normalized = set.trim().replace(/,/g, ' ')
    .replace(/(\d+(?:\.\d+){0,2})\s+-\s+(\d+(?:\.\d+){0,2})/g, (_, start, end) => {
      const endParts = end.split('.').map(Number);
      const upper = endParts.length === 1 ? `<${endParts[0] + 1}.0.0`
        : endParts.length === 2 ? `<${endParts[0]}.${endParts[1] + 1}.0` : `<=${end}`;
      return `>=${start} ${upper}`;
    })
    .replace(/(>=|<=|>|<|=|\^|~)\s+(?=\d)/g, '$1');
  if (!normalized || normalized === '*') return [];
  const predicates = [];
  for (const token of normalized.split(/\s+/).filter(Boolean)) {
    const expanded = expandToken(token);
    if (!expanded) return null;
    predicates.push(...expanded);
  }
  return predicates;
};

/** Return true/false for supported npm Node ranges and null rather than guessing for unknown syntax. */
export function satisfiesNodeRange(version, range) {
  const actual = parseVersion(version);
  if (!actual || typeof range !== 'string' || !range.trim()) return null;
  let supported = false;
  let unknown = false;
  for (const set of range.split('||')) {
    const predicates = predicatesForSet(set);
    if (predicates == null) { unknown = true; continue; }
    supported = true;
    if (predicates.every((predicate) => predicate(actual))) return true;
  }
  return supported && !unknown ? false : null;
}
