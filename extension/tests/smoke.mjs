import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extensionRoot = path.resolve(__dirname, "..");

const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, "manifest.json"), "utf8"));
assert.equal(manifest.manifest_version, 3);
assert.equal(manifest.background.type, "module");
assert.ok(manifest.content_scripts[0].js.includes("src/risk-engine.js"));

const riskEngineSource = fs.readFileSync(path.join(extensionRoot, "src", "risk-engine.js"), "utf8");
const sandbox = {
  globalThis: {},
  URL,
};
sandbox.globalThis = sandbox;
vm.runInNewContext(riskEngineSource, sandbox, { filename: "risk-engine.js" });

const result = sandbox.MailShieldRiskEngine.analyzeMailContext({
  subject: "URGENT: verify your account",
  senderEmail: "security@paypal-check.tk",
  replyTo: "help@paypal.com",
  fullText: "Your account will be suspended. Click login and verify your password now.",
  links: [{ href: "http://paypal-check.tk/login", text: "Verify now" }],
  attachments: ["statement.zip"],
});

assert.equal(result.label, 1);
assert.equal(result.verdict, "phishing");
assert.ok(result.score >= 50);
assert.equal(result.confidence, result.score / 100);
assert.ok(result.rule_features.credential_request);
assert.ok(result.reasons.length > 0);

console.log("extension smoke tests passed");
