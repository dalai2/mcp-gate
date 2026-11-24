// Reglas estáticas del OWASP MCP Top 10 (2025), edición beta.
//
// En alcance: MCP01, MCP03, MCP04, MCP05, MCP07, MCP09.
// Fuera de alcance a propósito (exigen llamar una tool o juzgar un
// transcript): MCP02, MCP06, MCP08, MCP10.

export const SCHEMA_URL =
  "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";
export const NPM_REGISTRY = "https://registry.npmjs.org";
export const DESCRIPTION_MAX = 100;

export const IN_SCOPE = ["MCP01", "MCP03", "MCP04", "MCP05", "MCP07", "MCP09"];
export const OUT_OF_SCOPE = ["MCP02", "MCP06", "MCP08", "MCP10"];

const SECRET_RES = [
  /AKIA[0-9A-Z]{16}/,
  /\bsk-[A-Za-z0-9]{20,}/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
  /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/,
  /\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['"][^'"]{8,}['"]/i,
];

// Las agujas van partidas para que este archivo no se marque a si mismo.
const POISON_RES = [
  new RegExp(["ignore (?:all |any )?(?:previous|prior|above) ", "instructions"].join(""), "i"),
  new RegExp(["disregard (?:the )?(?:system|", "developer|user)"].join(""), "i"),
  new RegExp(["do not tell ", "the user"].join(""), "i"),
  new RegExp(["bypass (?:the )?(?:approval|policy|confirmation|", "safety)"].join(""), "i"),
  new RegExp(["send (?:all |the )?(?:secrets|tokens|credentials|api ", "keys)"].join(""), "i"),
  new RegExp(["exfil", "trat"].join(""), "i"),
  new RegExp(["<IMPORT", "ANT>"].join(""), "i"),
];

const WRITE_RE = /\b(delete|drop|overwrite|destroy|wipe|execute|kill|write|update|send|post|publish|remove)\b/i;
const DESTROY_RE = /\b(delete|drop|destroy|wipe|overwrite)\b/i;
const SHELL_PROPS = new Set(["command", "cmd", "shell", "script", "exec", "bash"]);
const PINNED = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const SERVER_NAME = /^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9._-]*$/;
const FLOATING = new Set(["*", "latest", "next", ""]);

export function finding(id, severity, message, where = "") {
  return { id, severity, message, where };
}

export function fails(findings) {
  return findings.filter((f) => f.severity === "fail");
}

export function okReport(findings, extra = {}) {
  return { ok: fails(findings).length === 0, findings, ...extra };
}

function hit(re, text) {
  const matched = re.test(text);
  re.lastIndex = 0;
  return matched;
}

export function scanText(text, where, findings) {
  const s = String(text ?? "");
  for (const re of SECRET_RES) {
    if (hit(re, s)) {
      findings.push(finding("MCP01", "fail", "Hard-coded secret pattern", where));
      break;
    }
  }
  for (const re of POISON_RES) {
    if (hit(re, s)) {
      findings.push(finding("MCP03", "fail", "Hidden-instruction pattern", where));
      break;
    }
  }
}

export function scoreTool(tool, findings) {
  const name = tool?.name || "(unnamed)";
  if (!tool?.name || !tool.description || !tool.inputSchema) {
    findings.push(finding(
      "MCP03",
      "fail",
      "Tool is missing name, description, or inputSchema",
      name,
    ));
  }
  scanText(tool?.description, `tool ${name} description`, findings);
  scanText(JSON.stringify(tool?.inputSchema ?? {}), `tool ${name} inputSchema`, findings);

  const ann = tool?.annotations;
  if (!ann) {
    findings.push(finding(
      "MCP03",
      "warn",
      "Tool has no annotations (readOnlyHint, destructiveHint)",
      name,
    ));
  } else {
    const desc = String(tool.description || "");
    if (ann.readOnlyHint === true && hit(WRITE_RE, desc)) {
      findings.push(finding(
        "MCP03",
        "fail",
        "readOnlyHint is true but the description names a write or a send",
        name,
      ));
    }
    if (ann.destructiveHint === false && hit(DESTROY_RE, desc)) {
      findings.push(finding(
        "MCP03",
        "fail",
        "destructiveHint is false but the description names a destructive action",
        name,
      ));
    }
  }

  const schema = tool?.inputSchema || {};
  if (schema.type === "object" && schema.additionalProperties !== false) {
    findings.push(finding(
      "MCP05",
      "warn",
      "inputSchema does not set additionalProperties to false",
      name,
    ));
  }
  const props = schema.properties || {};
  for (const [key, def] of Object.entries(props)) {
    if (SHELL_PROPS.has(key) && def && def.type === "string" && !Array.isArray(def.enum)) {
      findings.push(finding(
        "MCP05",
        "fail",
        `Parameter "${key}" is a free-form command string`,
        name,
      ));
    }
  }
}

export function repoUrl(pkg) {
  const repo = pkg.repository;
  if (!repo) return "";
  if (typeof repo === "string") return repo;
  return repo.url || "";
}

export function githubOwner(url) {
  const m = String(url).match(/github\.com[:/]([^/]+)/i);
  return m ? m[1].replace(/\.git$/i, "") : "";
}

export function binRel(pkg) {
  if (!pkg.bin) return "";
  if (typeof pkg.bin === "string") return pkg.bin;
  const first = Object.values(pkg.bin)[0];
  return typeof first === "string" ? first : "";
}

export function serverDescription(pkg) {
  return String(pkg.mcpDescription || pkg.description || "").trim();
}

export function checkIdentity(pkg, server, findings) {
  const desc = serverDescription(pkg);
  if (!desc) {
    findings.push(finding("MCP04", "fail", "Package description is empty", "package.json"));
  } else if (desc.length > DESCRIPTION_MAX) {
    findings.push(finding(
      "MCP04",
      "fail",
      `Description is ${desc.length} characters; the registry limit is ${DESCRIPTION_MAX}`,
      "package.json",
    ));
  }
  scanText(desc, "package.json description", findings);

  if (!PINNED.test(String(pkg.version || ""))) {
    findings.push(finding(
      "MCP04",
      "fail",
      "Version is not a pinned semver",
      "package.json",
    ));
  }

  const name = String(pkg.mcpName || "");
  if (!name) {
    findings.push(finding("MCP04", "fail", "mcpName is missing", "package.json"));
  } else if (!SERVER_NAME.test(name)) {
    findings.push(finding(
      "MCP04",
      "fail",
      "mcpName must look like io.github.owner/server",
      "package.json",
    ));
  }
  if (server && name && server.name !== name) {
    findings.push(finding(
      "MCP04",
      "fail",
      "server.json name does not match package.json mcpName",
      "server.json",
    ));
  }

  const owner = githubOwner(repoUrl(pkg)).toLowerCase();
  if (owner && name && !name.startsWith(`io.github.${owner}/`)) {
    findings.push(finding(
      "MCP04",
      "fail",
      `mcpName must start with io.github.${owner}/`,
      "package.json",
    ));
  }

  const deps = { ...(pkg.dependencies || {}), ...(pkg.optionalDependencies || {}) };
  for (const [dep, range] of Object.entries(deps)) {
    const bare = String(range).trim().replace(/^[~^]/, "");
    if (FLOATING.has(String(range).trim())) {
      findings.push(finding(
        "MCP04",
        "fail",
        `Dependency ${dep} is not pinned (${range || "empty"})`,
        "package.json",
      ));
    } else if (/^[~^]/.test(String(range))) {
      findings.push(finding(
        "MCP04",
        "warn",
        `Dependency ${dep} uses a range (${range}); the lockfile is the pin`,
        "package.json",
      ));
    } else if (!PINNED.test(bare)) {
      findings.push(finding(
        "MCP04",
        "warn",
        `Dependency ${dep} version is not a semver pin (${range})`,
        "package.json",
      ));
    }
  }

  if (!server) return;
  checkServer(pkg, server, findings);
}

export function checkServer(pkg, server, findings) {
  scanText(JSON.stringify(server), "server.json", findings);
  const packages = Array.isArray(server.packages) ? server.packages : [];
  if (packages.length === 0 && !(Array.isArray(server.remotes) && server.remotes.length)) {
    findings.push(finding("MCP04", "fail", "server.json has no packages", "server.json"));
  }
  for (const entry of packages) {
    if (entry.registryType && entry.registryType !== "npm") {
      findings.push(finding(
        "MCP04",
        "fail",
        `registryType ${entry.registryType} is outside this packager (npm only)`,
        "server.json",
      ));
    }
    if (entry.registryBaseUrl && entry.registryBaseUrl !== NPM_REGISTRY) {
      findings.push(finding(
        "MCP04",
        "fail",
        "registryBaseUrl must be https://registry.npmjs.org",
        "server.json",
      ));
    }
    if (entry.identifier && entry.identifier !== pkg.name) {
      findings.push(finding(
        "MCP04",
        "fail",
        "Package identifier does not match package.json name",
        "server.json",
      ));
    }
    if (entry.version && entry.version !== pkg.version) {
      findings.push(finding(
        "MCP04",
        "fail",
        "Package version does not match package.json version",
        "server.json",
      ));
    }
    const transport = entry.transport?.type;
    if (transport && transport !== "stdio") {
      findings.push(finding(
        "MCP07",
        "fail",
        `Transport ${transport} is outside this verifier (stdio only)`,
        "server.json",
      ));
    }
    if (entry.runtimeHint === "npx") {
      findings.push(finding(
        "MCP07",
        "warn",
        "runtimeHint npx does not spawn on Windows; the client needs cmd /c npx",
        "server.json",
      ));
    }
  }
  if (Array.isArray(server.remotes) && server.remotes.length > 0) {
    findings.push(finding(
      "MCP07",
      "fail",
      "A remote server is declared; this verifier only accepts stdio",
      "server.json",
    ));
  }
}
