// Text tokens in styles.css must meet WCAG AA (4.5:1) on every surface they
// are used over. Runs in CI; no dependencies.
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../internal/server/static/css/styles.css', import.meta.url), 'utf8');
const token = name => {
  const m = css.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  if (!m) throw new Error(`token --${name} not found`);
  return m[1];
};
const lum = hex => {
  const c = hex.slice(1).match(/../g).map(x => parseInt(x, 16) / 255)
    .map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

const surfaces = ['ink', 'ink-raised', 'ink-well'];
const text = ['paper', 'paper-muted', 'paper-dim', 'brass', 'ok', 'warn', 'bad'];
let failed = false;
for (const t of text) for (const s of surfaces) {
  const r = ratio(token(t), token(s));
  const ok = r >= 4.5;
  if (!ok) failed = true;
  console.log(`${ok ? 'ok  ' : 'FAIL'} --${t} on --${s}: ${r.toFixed(2)}`);
}
if (failed) process.exit(1);
