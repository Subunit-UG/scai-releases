// Jeder Workflow, der bei Pull Requests läuft, muss den Nachlauf der automatischen Freigabe
// auslösen. Sonst bleibt die Freigabe nach einem Neustart dieses Checks rot hängen, obwohl
// alles grün ist (Vorfall 28.10.2026, echo-releases#24). Gleiche Prüfung in echo-releases.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const WORKFLOWS = join(import.meta.dirname, "..", ".github", "workflows");
const unquote = (s) => s.trim().replace(/^["']|["']$/g, "");

function prWorkflows() {
  const out = [];
  for (const file of readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f))) {
    const text = readFileSync(join(WORKFLOWS, file), "utf8");
    const name = text.match(/^name:\s*(.+)$/m);
    assert.ok(name, `${file}: kein name:`);
    const inline = text.match(/^on:\s*\[([^\]]*)\]/m);
    const single = text.match(/^on:\s*([\w-]+)\s*$/m);
    const block = /^ {2}pull_request:/m.test(text);
    const triggers = inline ? inline[1].split(",").map(unquote) : single ? [single[1]] : [];
    if (block || triggers.includes("pull_request")) out.push({ file, name: unquote(name[1]) });
  }
  return out;
}

function nachlaufListe() {
  const text = readFileSync(join(WORKFLOWS, "auto-freigabe-nachlauf.yml"), "utf8");
  const m = text.match(/^ {4}workflows:\s*\[(.*)\]\s*$/m);
  assert.ok(m, "auto-freigabe-nachlauf.yml: workflows-Liste fehlt");
  return m[1].split(",").map(unquote);
}

test("findet die pull_request-Workflows", () => {
  assert.ok(prWorkflows().some((w) => w.name === "Freigabe-Tests"));
});

test("jeder pull_request-Workflow löst den Nachlauf aus", () => {
  const liste = nachlaufListe();
  const fehlend = prWorkflows().filter((w) => !liste.includes(w.name));
  assert.deepEqual(fehlend, [], "im Nachlauf (workflow_run.workflows) ergänzen");
});
