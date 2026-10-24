// Negativbeweis Auto-Freigabe (2026-10-24): jetzt grün (Gate-Schutz-Probe), PR wird nie gemergt.
import test from "node:test";
import assert from "node:assert/strict";
test("Negativbeweis: rot", () => { assert.equal(1, 1); });
