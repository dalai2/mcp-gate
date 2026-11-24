// Verifica un paquete ya empaquetado: archivos, server.json, y tools/list.
// No llama ninguna tool.

import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { listTools } from "./protocol.mjs";
import {
  binRel,
  checkIdentity,
  finding,
  okReport,
  scanText,
  scoreTool,
} from "./rules.mjs";

const CHECKSUM_NAME = "mcp-checksums.json";

export async function verify(dir, { entry, timeoutMs } = {}) {
  const root = path.resolve(dir);
  const findings = [];
  let pkg;
  try {
    pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  } catch (err) {
    return okReport([finding("MCP04", "fail", `Cannot read package.json: ${err.message}`, "package.json")]);
  }

  let server = null;
  try {
    server = JSON.parse(await readFile(path.join(root, "server.json"), "utf8"));
  } catch {
    findings.push(finding("MCP04", "fail", "server.json is missing; run pack first", "server.json"));
  }
  checkIdentity(pkg, server, findings);

  const rel = binRel(pkg);
  if (!rel) {
    findings.push(finding("MCP04", "fail", "package.json bin is missing", "package.json"));
  }
  if (entry && rel && path.normalize(entry) !== path.normalize(rel)) {
    findings.push(finding(
      "MCP09",
      "fail",
      `Entry ${entry} is not the bin this package installs (${rel})`,
      "package.json",
    ));
    return okReport(findings);
  }

  await checkChecksums(root, pkg, findings);
  await scanShipped(root, pkg, findings);

  if (!rel) return okReport(findings);
  const binPath = path.join(root, rel);
  try {
    const info = await stat(binPath);
    if (!info.isFile()) throw new Error("not a file");
  } catch {
    findings.push(finding("MCP07", "fail", `Bin does not exist: ${rel}`, "package.json"));
    return okReport(findings);
  }

  let live;
  try {
    live = await listTools({
      command: process.execPath,
      args: [binPath],
      cwd: root,
      timeoutMs,
    });
  } catch (err) {
    findings.push(finding(
      "MCP07",
      "fail",
      `Server did not complete initialize and tools/list: ${err.message}`,
      rel,
    ));
    return okReport(findings);
  }

  const announced = live.serverInfo?.name || "";
  if (announced && announced !== pkg.name) {
    findings.push(finding(
      "MCP09",
      "warn",
      `Process announced itself as ${announced}, package name is ${pkg.name}`,
      rel,
    ));
  }
  if (!Array.isArray(live.tools) || live.tools.length === 0) {
    findings.push(finding("MCP03", "warn", "Server listed no tools", rel));
  }
  for (const tool of live.tools || []) scoreTool(tool, findings);

  return okReport(findings, {
    toolCount: (live.tools || []).length,
    serverInfo: live.serverInfo,
  });
}

async function checkChecksums(root, pkg, findings) {
  let doc;
  try {
    doc = JSON.parse(await readFile(path.join(root, CHECKSUM_NAME), "utf8"));
  } catch {
    findings.push(finding(
      "MCP04",
      "fail",
      "mcp-checksums.json is missing; run pack first",
      CHECKSUM_NAME,
    ));
    return;
  }
  const files = doc.files || {};
  for (const [rel, expected] of Object.entries(files)) {
    try {
      const buf = await readFile(path.join(root, rel));
      const got = createHash("sha256").update(buf).digest("hex");
      if (got !== expected) {
        findings.push(finding("MCP04", "fail", "Checksum does not match", rel));
      }
    } catch {
      findings.push(finding("MCP04", "fail", "Checksummed file is missing", rel));
    }
  }
  const declared = Array.isArray(pkg.files) ? pkg.files : [];
  for (const rel of declared) {
    if (!files[rel.split("\\").join("/")] && !rel.endsWith("/")) {
      try {
        const info = await stat(path.join(root, rel));
        if (info.isFile()) {
          findings.push(finding("MCP04", "fail", "Shipped file has no checksum", rel));
        }
      } catch {
        // a missing optional file is not a checksum miss
      }
    }
  }
}

async function scanShipped(root, pkg, findings) {
  const names = new Set(["package.json", "server.json", "README.md", "LICENSE", binRel(pkg)]);
  for (const rel of pkg.files || []) names.add(rel);
  for (const rel of names) {
    if (!rel) continue;
    try {
      const buf = await readFile(path.join(root, rel));
      if (buf.length > 1_000_000) continue;
      scanText(buf.toString("utf8"), rel, findings);
    } catch {
      // absent optional files are ignored
    }
  }
}
