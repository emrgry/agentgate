/**
 * Masks obvious secrets in a command line for DISPLAY (phone, activity, push). Pure, no
 * dependencies (usable by API, daemon and mobile). Never apply to the hashed/executed
 * command. Heuristic: it reduces accidental exposure, it is not a guarantee.
 */
const MASK = "***";

const RULES: Array<[RegExp, string]> = [
  // URLs with credentials: scheme://user:pass@host → scheme://user:***@host
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)[^\s/@]+@/gi, `$1${MASK}@`],
  // Authorization headers / bearer & basic tokens
  [/\b(authorization\s*:\s*(?:bearer|basic|token)?\s*)[^\s'"]+/gi, `$1${MASK}`],
  [/\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, `$1${MASK}`],
  // Well-known token formats
  [/\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}/g, `$1_$2_${MASK}`],
  [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}/g, `sk-${MASK}`],
  [/\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, `$1_${MASK}`],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, `github_pat_${MASK}`],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, `glpat-${MASK}`],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, `xox-${MASK}`],
  [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, `$1${MASK}`],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, `AIza${MASK}`],
  [/\bnpm_[A-Za-z0-9]{30,}/g, `npm_${MASK}`],
  // KEY=value / --key value / --key=value for secret-ish names
  [
    /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Za-z0-9_]*=)(?:'[^']*'|"[^"]*"|[^\s;&|]+)/gi,
    `$1${MASK}`,
  ],
  [/(--?(?:password|passwd|pass|secret|token|api-key|apikey|access-key|auth-token)(?:=|\s+))(?:'[^']*'|"[^"]*"|[^\s;&|]+)/gi, `$1${MASK}`],
  // mysql-family inline password: -pSECRET (not `mkdir -p`)
  [/(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]*?\s-p)(?!\s)[^\s;&|]+/g, `$1${MASK}`],
  // PEM blocks
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, `-----BEGIN PRIVATE KEY-----${MASK}-----END PRIVATE KEY-----`],
];

export function redactCommandSecrets(command: string): string {
  let out = command;
  for (const [re, rep] of RULES) out = out.replace(re, rep);
  return out;
}
