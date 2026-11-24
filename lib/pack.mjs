// Escribe server.json y mcp-checksums.json. No publica.

import { createHash } from "node:crypto";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  NPM_REGISTRY,
  SCHEMA_URL,
  binRel,
  checkIdentity,
  checkServer,
  fails,
  finding,
  okReport,
  repoUrl,
  scanText,
  serverDescription,
} from "./rules.mjs";

const SKIP_DIR = new Set(["node_modules", ".git", "dist", "coverage"]);
const TEXT_EXT = new Set([
  ".mjs", ".js", ".cjs", ".ts", ".json", ".md", ".txt",
  ".yml", ".yaml", ".toml", ".ps1", ".sh", ".env",
]);
const CHECKSUM_NAME = "mcp-checksums.json";
const SERVER_NAME = "server.json";

export async function pack(dir) {
  const root = path.resolve(dir);
  const findings = [];
  let pkg;
  try {
    pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  } catch (err) {
    return okReport([finding("MCP04", "fail", `Cannot read package.json: ${err.message}`, "package.json")]);
  }

  if (!pkg.mcpName) {
    const owner = ownerOf(pkg);
    const slug = String(pkg.name || "").replace(/^@[^/]+\//, "");
    if (owner && slug) pkg = { ...pkg, mcpName: `io.github.${owner.toLowerCase()}/${slug}` };
  }

  checkIdentity(pkg, null, findings);
  if (!binRel(pkg)) {
    findings.push(finding("MCP04", "fail", "package.json bin is missing", "package.json"));
  } else {
    const binPath = path.join(root, binRel(pkg));
    try {
      const info = await stat(binPath);
      if (!info.isFile()) throw new Error("not a file");
    } catch {
      findings.push(finding("MCP07", "fail", `Bin does not exist: ${binRel(pkg)}`, "package.json"));
    }
  }

  const deps = { ...(pkg.dependencies || {}), ...(pkg.optionalDependencies || {}) };
  if (Object.keys(deps).length > 0) {
    try {
      await stat(path.join(root, "package-lock.json"));
    } catch {
      findings.push(finding(
        "MCP04",
        "fail",
        "Dependencies are declared and package-lock.json is missing",
        "package.json",
      ));
    }
  }

  const shipped = await shippedFiles(root, pkg);
  for (const rel of shipped) {
    if (rel === CHECKSUM_NAME || rel === "package-lock.json") continue;
    const ext = path.extname(rel).toLowerCase();
    if (rel.startsWith(".env") || TEXT_EXT.has(ext) || rel.endsWith(".env")) {
      const abs = path.join(root, rel);
      const info = await stat(abs);
      if (info.size > 1_000_000) {
        findings.push(finding("MCP01", "warn", "File is too large to scan", rel));
        continue;
      }
      const text = await readFile(abs, "utf8");
      scanText(text, rel, findings);
    }
  }

  if (fails(findings).length > 0) return okReport(findings);

  const server = buildServer(pkg);
  checkServer(pkg, server, findings);
  if (fails(findings).length > 0) return okReport(findings);

  const serverPath = path.join(root, SERVER_NAME);
  await writeFile(serverPath, JSON.stringify(server, null, 2) + "\n");

  const hashed = [...new Set([...shipped, SERVER_NAME])].filter((rel) => rel !== CHECKSUM_NAME).sort();
  const files = {};
  for (const rel of hashed) {
    const buf = await readFile(path.join(root, rel));
    files[rel.split(path.sep).join("/")] = createHash("sha256").update(buf).digest("hex");
  }
  const checksums = { algorithm: "sha256", files };
  await writeFile(
    path.join(root, CHECKSUM_NAME),
    JSON.stringify(checksums, null, 2) + "\n",
  );

  const onDisk = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  if (pkg.mcpName && !onDisk.mcpName) {
    const raw = await readFile(path.join(root, "package.json"), "utf8");
    const inserted = raw.replace(
      /\{/,
      `{\n  "mcpName": ${JSON.stringify(pkg.mcpName)},`,
    );
    await writeFile(path.join(root, "package.json"), inserted);
    files["package.json"] = createHash("sha256")
      .update(await readFile(path.join(root, "package.json")))
      .digest("hex");
    await writeFile(
      path.join(root, CHECKSUM_NAME),
      JSON.stringify({ algorithm: "sha256", files }, null, 2) + "\n",
    );
  }

  return okReport(findings, { server, checksums });
}

function ownerOf(pkg) {
  const url = repoUrl(pkg);
  const m = String(url).match(/github\.com[:/]([^/]+)/i);
  return m ? m[1].replace(/\.git$/i, "") : "";
}

function buildServer(pkg) {
  const server = {
    $schema: SCHEMA_URL,
    name: pkg.mcpName,
    description: serverDescription(pkg),
    version: pkg.version,
    packages: [
      {
        registryType: "npm",
        registryBaseUrl: NPM_REGISTRY,
        identifier: pkg.name,
        version: pkg.version,
        transport: { type: "stdio" },
      },
    ],
  };
  const url = repoUrl(pkg);
  if (url) {
    server.repository = {
      url: url.replace(/^git\+/, "").replace(/\.git$/, ""),
      source: "github",
    };
  }
  return server;
}

async function shippedFiles(root, pkg) {
  const listed = Array.isArray(pkg.files) && pkg.files.length > 0
    ? await expandFiles(root, pkg.files)
    : await walk(root);
  const extra = ["package.json", "README.md", "LICENSE", binRel(pkg)].filter(Boolean);
  const found = [];
  for (const rel of [...listed, ...extra]) {
    const norm = rel.split(path.sep).join("/");
    if (!norm || norm === CHECKSUM_NAME || SKIP_DIR.has(norm.split("/")[0])) continue;
    try {
      const info = await stat(path.join(root, norm));
      if (info.isFile()) found.push(norm);
    } catch {
      // README or LICENSE may be absent; a missing bin is reported elsewhere.
    }
  }
  return [...new Set(found)];
}

async function expandFiles(root, patterns) {
  const out = [];
  for (const pattern of patterns) {
    const rel = pattern.split(path.sep).join("/");
    try {
      const info = await stat(path.join(root, rel));
      if (info.isFile()) out.push(rel);
      else if (info.isDirectory()) out.push(...await walk(root, rel));
    } catch {
      out.push(rel);
    }
  }
  return out;
}

async function walk(root, rel = "") {
  const out = [];
  let entries;
  try {
    entries = await readdir(path.join(root, rel), { withFileTypes: true });
  } catch {
    return out;
  }
  for (const ent of entries) {
    if (SKIP_DIR.has(ent.name)) continue;
    const next = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...await walk(root, next));
    else if (ent.isFile()) out.push(next);
  }
  return out;
}
