import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { FACETS, type Facet, facetFor, LLM_SDK, RULES, type Severity, type SourceFile } from "./rules.ts";

export type Finding = {
  rule: string;
  title: string;
  severity: Severity;
  facet: Facet;
  file: string;
  line: number;
  snippet: string; // secrets redacted
  why: string;
  fix: string;
};

export type Report = {
  root: string;
  scannedAt: string;
  files: number;
  findings: Finding[];
  score: number;
  facets: { id: Facet; label: string; blurb: string; files: number; score: number; counts: Record<Severity, number> }[];
};

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "target", "coverage", ".turbo", "out"]);
const MAX_FILES = 4000;
const MAX_BYTES = 512 * 1024;
const TEXT = /\.(m?[jt]sx?|json|py|rs|go|sol|vue|svelte|ya?ml|toml|tf|env|sh)$|(^|\/)(Dockerfile[\w.-]*|\.env[\w.-]*)$/i;
const PENALTY: Record<Severity, number> = { critical: 35, high: 15, medium: 5 };

/** Files that are committed, or would be (respects .gitignore). Falls back to a directory walk. */
function listFiles(root: string): string[] {
  try {
    const out = execFileSync("git", ["-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.split("\0").filter(Boolean).slice(0, MAX_FILES);
  } catch {
    const acc: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        if (acc.length >= MAX_FILES) return;
        if (SKIP_DIRS.has(name)) continue;
        const full = join(dir, name);
        const st = statSync(full);
        if (st.isDirectory()) walk(full);
        else acc.push(relative(root, full));
      }
    };
    walk(root);
    return acc;
  }
}

/** Never show secret values on screen, even in a security report. */
export function redact(line: string): string {
  return line
    .replace(/\[\s*(?:\d{1,3}\s*,\s*){20,}\d{1,3}\s*\]?/g, "[REDACTED key bytes]")
    .replace(/(0x)?[0-9a-fA-F]{64}/g, "$1[REDACTED]")
    .replace(/[1-9A-HJ-NP-Za-km-z]{80,90}/g, "[REDACTED]")
    .replace(/(["'`])([a-z]{3,8}\s+){11,23}[a-z]{3,8}\1/gi, "$1[REDACTED seed phrase]$1")
    .replace(/^(\s*\w*(PRIVATE|SECRET|MNEMONIC|SEED|API_KEY)\w*\s*=\s*)\S+/i, "$1[REDACTED]")
    .replace(/(\/v\d+\/)[0-9a-zA-Z_-]{20,}/g, "$1[REDACTED]") // API keys embedded in RPC URLs
    .replace(/(api[-_]?key=)[^&\s"'`]+/gi, "$1[REDACTED]")
    .trim()
    .slice(0, 220);
}

export function scan(root: string): Report {
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`Not a directory: ${root}`);
  // .codeguardignore: one path prefix per line, like a tiny .gitignore.
  const ignoreFile = join(root, ".codeguardignore");
  const ignored = existsSync(ignoreFile)
    ? readFileSync(ignoreFile, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    : [];
  const paths = listFiles(root).filter(
    (p) => TEXT.test(p) && !p.split("/").some((seg) => SKIP_DIRS.has(seg)) && !ignored.some((prefix) => p.startsWith(prefix)),
  );
  const findings: Finding[] = [];
  const filesPerFacet: Record<Facet, number> = { frontend: 0, backend: 0, cloud: 0, agent: 0, onchain: 0 };

  for (const path of paths) {
    const full = join(root, path);
    let content: string;
    try {
      if (statSync(full).size > MAX_BYTES) continue;
      content = readFileSync(full, "utf8");
    } catch {
      continue;
    }
    // A file that talks to an LLM is agent code, wherever it lives.
    const facet = /\.(m?[jt]sx?|py)$/.test(path) && LLM_SDK.test(content) ? "agent" : facetFor(path);
    const file: SourceFile = { path, content, lines: content.split("\n"), facet };
    filesPerFacet[file.facet]++;
    for (const rule of RULES) {
      if (rule.appliesTo && !rule.appliesTo(file)) continue;
      for (const hit of rule.find(file)) {
        findings.push({
          rule: rule.id,
          title: rule.title,
          severity: rule.severity,
          facet: rule.facet ?? file.facet,
          file: path,
          line: hit.line,
          snippet: redact(file.lines[hit.line - 1] ?? ""),
          why: rule.why,
          fix: rule.fix,
        });
      }
    }
  }

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);

  const scoreOf = (fs: Finding[]) => Math.max(0, 100 - fs.reduce((s, f) => s + PENALTY[f.severity], 0));
  const facets = FACETS.map((f) => {
    const mine = findings.filter((x) => x.facet === f.id);
    return {
      ...f,
      files: filesPerFacet[f.id],
      score: scoreOf(mine),
      counts: {
        critical: mine.filter((x) => x.severity === "critical").length,
        high: mine.filter((x) => x.severity === "high").length,
        medium: mine.filter((x) => x.severity === "medium").length,
      },
    };
  });

  return { root, scannedAt: new Date().toISOString(), files: paths.length, findings, score: scoreOf(findings), facets };
}
