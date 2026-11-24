// Cliente stdio mínimo: initialize + tools/list. No llama tools.

import { spawn } from "node:child_process";

export function listTools({ command, args, cwd, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let buf = "";
    let stderr = "";
    const pending = new Map();
    let nextId = 1;
    let settled = false;

    function finish(err, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const waiter of pending.values()) {
        waiter.rej(new Error("server closed"));
      }
      pending.clear();
      child.kill();
      if (err) {
        err.stderr = redact(stderr);
        reject(err);
      } else {
        resolve(value);
      }
    }

    const timer = setTimeout(
      () => finish(new Error("timed out waiting for the server")),
      timeoutMs,
    );

    function send(method, params) {
      const id = nextId++;
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      return new Promise((res, rej) => pending.set(id, { res, rej }));
    }

    child.stdout.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id != null && pending.has(msg.id)) {
          const waiter = pending.get(msg.id);
          pending.delete(msg.id);
          if (msg.error) waiter.rej(new Error(msg.error.message || "JSON-RPC error"));
          else waiter.res(msg.result || {});
        }
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-2000);
    });
    child.on("error", (err) => finish(err));
    child.on("exit", (code) => {
      if (!settled) finish(new Error(`server exited before tools/list (${code})`));
    });

    (async () => {
      try {
        const init = await send("initialize", {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-gate", version: "1.0.0" },
        });
        child.stdin.write(JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }) + "\n");
        const tools = [];
        let cursor;
        for (let page = 0; page < 20; page++) {
          const result = await send("tools/list", cursor ? { cursor } : {});
          if (Array.isArray(result.tools)) tools.push(...result.tools);
          cursor = result.nextCursor;
          if (!cursor) break;
        }
        finish(null, {
          serverInfo: init.serverInfo || {},
          protocolVersion: init.protocolVersion || "",
          tools,
        });
      } catch (err) {
        finish(err);
      }
    })();
  });
}

export function redact(text) {
  return String(text || "")
    .replace(/AKIA[0-9A-Z]{16}/g, "[redacted]")
    .replace(/\bsk-[A-Za-z0-9]{20,}/g, "[redacted]")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[redacted]");
}
