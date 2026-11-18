// Turns a deterministic scan report into an executive summary + fix plan.
// Claude only sees redacted findings, and is told not to add findings of its own.
import Anthropic from "@anthropic-ai/sdk";
import type { Report } from "./scan.ts";

const client = new Anthropic();

export async function explain(clientName: string, report: Report): Promise<string> {
  const findings = report.findings.slice(0, 60).map((f) => ({
    severity: f.severity,
    facet: f.facet,
    title: f.title,
    where: `${f.file}:${f.line}`,
    snippet: f.snippet, // already redacted
  }));

  const response = await client.beta.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 4000,
    output_config: { effort: "low" },
    betas: ["server-side-fallback-2026-07-01"],
    fallbacks: "default",
    system:
      "You are a security lead at a crypto company, briefing an engineering manager. " +
      "Use ONLY the findings provided; do not invent issues, files or numbers. " +
      "Write plain prose with short paragraphs, no markdown headings, no tables.",
    messages: [
      {
        role: "user",
        content:
          `Client: ${clientName}\nOverall score: ${report.score}/100 across ${report.files} files.\n` +
          `Facet scores: ${report.facets.map((f) => `${f.label} ${f.score}`).join(", ")}\n\n` +
          `Findings (JSON):\n${JSON.stringify(findings)}\n\n` +
          "Write: (1) a two-sentence verdict on how exposed this company's funds are; " +
          "(2) the three fixes to do first, in order, each one line naming the file; " +
          "(3) one sentence on what to do about any AI-agent findings. Under 180 words total.",
      },
    ],
  });

  if (response.stop_reason === "refusal") return "The model declined to summarize this report.";
  return response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n").trim();
}
