import { spawn, type ChildProcess } from "node:child_process";
import * as http from "node:http";
import * as readline from "node:readline";

const port = Number(process.env.REA_BRIDGE_PORT ?? 7801);
const npxCommand = process.platform === "win32" ? "npx.cmd" : "npx";

type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void };

class REABridge {
  private child: ChildProcess;
  private rl: readline.Interface;
  private nextId = 0;
  private pending = new Map<number, Pending>();
  private ready = false;

  constructor() {
    this.child = spawn(npxCommand, ["-y", "rea-agents@latest", "mcp"], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env },
      windowsHide: true,
    });
    this.rl = readline.createInterface({ input: this.child.stdout! });
    this.rl.on("line", (line) => this.handleLine(line));
    this.child.stderr?.on("data", (data) => process.stderr.write(`[REA] ${data}`));
    this.child.on("exit", (code) => {
      for (const request of this.pending.values()) request.reject(new Error(`REA exited with ${code}`));
      this.pending.clear();
      this.ready = false;
    });
  }

  private handleLine(line: string) {
    try {
      const message = JSON.parse(line);
      if (typeof message.id !== "number") return;
      const request = this.pending.get(message.id);
      if (!request) return;
      this.pending.delete(message.id);
      if (message.error) request.reject(new Error(JSON.stringify(message.error)));
      else request.resolve(message.result);
    } catch {
      // Ignore non-JSON diagnostic output from the child process.
    }
  }

  private send(method: string, params: unknown): Promise<unknown> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`Timeout: ${method}`));
      }, 120_000);
    });
  }

  async initialize() {
    if (this.ready) return;
    await this.send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "pct-rea-bridge", version: "1.0.0" },
    });
    this.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    this.ready = true;
  }

  async listTools() { await this.initialize(); return this.send("tools/list", {}); }
  async callTool(name: string, args: Record<string, unknown>) {
    await this.initialize();
    return this.send("tools/call", { name, arguments: args });
  }
  shutdown() { this.child.kill(); }
}

const bridge = new REABridge();
const server = http.createServer((request, response) => {
  if (request.method !== "POST") { response.writeHead(405).end(); return; }
  let body = "";
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", async () => {
    try {
      const input = JSON.parse(body);
      const result = input.method === "list_tools"
        ? await bridge.listTools()
        : input.method === "call_tool"
          ? await bridge.callTool(input.params?.name, input.params?.arguments ?? {})
          : (() => { throw new Error(`Unknown method ${input.method}`); })();
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ ok: true, result }));
    } catch (error) {
      response.writeHead(500, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ ok: false, error: String(error) }));
    }
  });
});

server.listen(port, "127.0.0.1", () => console.log(`[rea-bridge] listening on 127.0.0.1:${port}`));
const shutdown = () => { bridge.shutdown(); server.close(() => process.exit(0)); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
