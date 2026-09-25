import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import * as http2 from "node:http2";
import * as net from "node:net";
import * as tls from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";

import { closeMiosaConnections, miosa } from "../index";

const API_KEY = "msk_test_0123456789abcdef";
const SANDBOX_ID = "a1b2c3d4-0000-0000-0000-000000000001";
const POOL_SIZE = 16;

function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function selfSignedCert(): { key: string; cert: string } {
  const dir = mkdtempSync(join(tmpdir(), "miosa-h2-"));
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        join(dir, "key.pem"),
        "-out",
        join(dir, "cert.pem"),
      ],
      { stdio: "ignore" },
    );
    return {
      key: readFileSync(join(dir, "key.pem"), "utf8"),
      cert: readFileSync(join(dir, "cert.pem"), "utf8"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

type StreamHandler = (
  stream: http2.ServerHttp2Stream,
  headers: http2.IncomingHttpHeaders,
  context: { session: http2.ServerHttp2Session; streamIndex: number },
) => void;

interface TestServer {
  baseUrl: string;
  sessions: http2.ServerHttp2Session[];
  streamsBySession: Map<http2.ServerHttp2Session, number>;
  streamCount: () => number;
  close: () => Promise<void>;
}

function respondSandbox(stream: http2.ServerHttp2Stream, status = 200): void {
  stream.respond({ ":status": status, "content-type": "application/json" });
  stream.end(
    JSON.stringify({
      data: {
        id: SANDBOX_ID,
        slug: "a1b2c3d4",
        name: null,
        state: "running",
        template_id: null,
        cpu_count: 2,
        memory_mb: 4096,
        timeout_sec: 300,
        metadata: null,
        preview_url: null,
        preview_domain: null,
        created_at: "2026-07-11T00:00:00Z",
      },
    }),
  );
}

// An HTTP/2 TLS server whose handshake for the Nth accepted connection is
// delayed by handshakeDelayMs(N), so tests control when each pooled session
// becomes ready.
async function startServer(
  credentials: { key: string; cert: string },
  options: {
    handshakeDelayMs?: (connectionIndex: number) => number;
    onStream?: StreamHandler;
  } = {},
): Promise<TestServer> {
  const secure = http2.createSecureServer({
    ...credentials,
    allowHTTP1: false,
  });
  const sessions: http2.ServerHttp2Session[] = [];
  const streamsBySession = new Map<http2.ServerHttp2Session, number>();
  const sockets = new Set<net.Socket>();
  let streamIndex = 0;

  secure.on("session", (session) => {
    sessions.push(session);
    streamsBySession.set(session, 0);
  });
  secure.on("stream", (stream, headers) => {
    // Tests reset streams on purpose; that must not crash the server.
    stream.on("error", () => undefined);
    const session = stream.session as http2.ServerHttp2Session;
    streamsBySession.set(session, (streamsBySession.get(session) ?? 0) + 1);
    const context = { session, streamIndex: streamIndex++ };
    if (options.onStream) options.onStream(stream, headers, context);
    else respondSandbox(stream);
  });

  let connectionIndex = 0;
  const tcp = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    const delay = options.handshakeDelayMs?.(connectionIndex++) ?? 0;
    setTimeout(() => secure.emit("connection", socket), delay);
  });
  await new Promise<void>((resolve) => tcp.listen(0, "127.0.0.1", resolve));
  const { port } = tcp.address() as net.AddressInfo;

  return {
    baseUrl: `https://127.0.0.1:${port}/api/v1`,
    sessions,
    streamsBySession,
    streamCount: () => streamIndex,
    close: async () => {
      for (const session of sessions) session.destroy();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => tcp.close(() => resolve()));
    },
  };
}

function h2Frame(
  type: number,
  flags: number,
  streamId: number,
  payload = Buffer.alloc(0),
): Buffer {
  const header = Buffer.alloc(9);
  header.writeUIntBE(payload.length, 0, 3);
  header[3] = type;
  header[4] = flags;
  header.writeUInt32BE(streamId, 5);
  return Buffer.concat([header, payload]);
}

// Node's HTTP/2 server clamps goaway()'s last-stream-id to the last stream it
// received, so it cannot reject a stream the way a draining proxy does. This
// speaks just enough raw HTTP/2 to answer the first HEADERS frame with
// GOAWAY(last-stream-id=0) and every later one with a 200 sandbox response.
async function startRawGoawayServer(credentials: {
  key: string;
  cert: string;
}): Promise<{
  baseUrl: string;
  headersFrames: () => number;
  close: () => Promise<void>;
}> {
  const SETTINGS = 0x4;
  const HEADERS = 0x1;
  const DATA = 0x0;
  const GOAWAY = 0x7;
  const body = Buffer.from(
    JSON.stringify({
      data: {
        id: SANDBOX_ID,
        state: "running",
        created_at: "2026-07-11T00:00:00Z",
      },
    }),
  );
  let headersFrames = 0;
  const sockets = new Set<net.Socket>();

  const server = tls.createServer(
    { ...credentials, ALPNProtocols: ["h2"] },
    (socket) => {
      socket.on("error", () => undefined);
      socket.write(h2Frame(SETTINGS, 0, 0));
      let buffered = Buffer.alloc(0);
      let prefaceRead = false;
      socket.on("data", (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (!prefaceRead) {
          if (buffered.length < 24) return;
          buffered = buffered.subarray(24);
          prefaceRead = true;
        }
        while (buffered.length >= 9) {
          const length = buffered.readUIntBE(0, 3);
          if (buffered.length < 9 + length) break;
          const type = buffered[3];
          const flags = buffered[4]!;
          const streamId = buffered.readUInt32BE(5) & 0x7fffffff;
          buffered = buffered.subarray(9 + length);
          if (type === SETTINGS && !(flags & 0x1))
            socket.write(h2Frame(SETTINGS, 0x1, 0));
          if (type !== HEADERS) continue;
          if (headersFrames++ === 0) {
            // last-stream-id 0, NO_ERROR: every open stream was never processed.
            socket.write(h2Frame(GOAWAY, 0, 0, Buffer.alloc(8)));
          } else {
            // 0x88 is HPACK static-table index 8, ":status: 200". END_HEADERS.
            socket.write(h2Frame(HEADERS, 0x4, streamId, Buffer.from([0x88])));
            socket.write(h2Frame(DATA, 0x1, streamId, body));
          }
        }
      });
    },
  );
  // Track raw TCP sockets, not TLS ones: pooled sessions still mid-handshake
  // would otherwise hold server.close() open.
  server.on("connection", (socket: net.Socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as net.AddressInfo;

  return {
    baseUrl: `https://127.0.0.1:${port}/api/v1`,
    headersFrames: () => headersFrames,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function until(
  predicate: () => boolean,
  timeoutMs = 2000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe.skipIf(!hasOpenssl())("HTTP/2 session pool", () => {
  let credentials: { key: string; cert: string };
  let server: TestServer | undefined;
  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    NODE_TLS_REJECT_UNAUTHORIZED: process.env.NODE_TLS_REJECT_UNAUTHORIZED,
  };

  beforeAll(() => {
    credentials = selfSignedCert();
  });

  beforeEach(() => {
    // The pooled transport is disabled under NODE_ENV=test so the mocked
    // fetch suite stays hermetic; this suite exercises it against a real
    // local server with a self-signed certificate.
    process.env.NODE_ENV = "production";
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  });

  afterEach(async () => {
    closeMiosaConnections();
    await server?.close();
    server = undefined;
    process.env.NODE_ENV = savedEnv.NODE_ENV;
    if (savedEnv.NODE_TLS_REJECT_UNAUTHORIZED === undefined)
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else
      process.env.NODE_TLS_REJECT_UNAUTHORIZED =
        savedEnv.NODE_TLS_REJECT_UNAUTHORIZED;
  });

  afterAll(() => {
    closeMiosaConnections();
  });

  it("should send on the first connected session without waiting for the rest of the pool", async () => {
    // One fast handshake, fifteen that take 800ms: requests must not wait
    // for the slow ones (the old quorum gate held them for 250ms).
    server = await startServer(credentials, {
      handshakeDelayMs: (index) => (index === 0 ? 0 : 800),
    });
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });

    const started = Date.now();
    const results = await Promise.all(
      Array.from({ length: 20 }, () => provider.sandbox.getById(SANDBOX_ID)),
    );
    const elapsed = Date.now() - started;

    expect(results.every((result) => result?.sandboxId === SANDBOX_ID)).toBe(
      true,
    );
    expect(elapsed).toBeLessThan(200);
    expect(server.sessions).toHaveLength(1);
  });

  it("should round-robin across every ready session once the pool is warm", async () => {
    server = await startServer(credentials);
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });
    await provider.sandbox.getById(SANDBOX_ID);
    await until(() => server!.sessions.length === POOL_SIZE);
    // Server-side session creation precedes the client's connect event.
    await new Promise((resolve) => setTimeout(resolve, 50));

    await Promise.all(
      Array.from({ length: POOL_SIZE * 2 }, () =>
        provider.sandbox.getById(SANDBOX_ID),
      ),
    );

    const used = Array.from(server.streamsBySession.values()).filter(
      (count) => count > 0,
    );
    expect(used).toHaveLength(POOL_SIZE);
  });

  it("should never open a stream on a session that is closed or received GOAWAY", async () => {
    server = await startServer(credentials);
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });
    await provider.sandbox.getById(SANDBOX_ID);
    await until(() => server!.sessions.length === POOL_SIZE);
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Record the state of every client session a stream is opened on.
    const probe = http2.connect(server.baseUrl);
    probe.on("error", () => undefined);
    const prototype = Object.getPrototypeOf(probe) as {
      request: (...args: unknown[]) => http2.ClientHttp2Stream;
    };
    probe.destroy();
    const original = prototype.request;
    const openedOn: Array<{ closed: boolean; destroyed: boolean }> = [];
    prototype.request = function (
      this: http2.ClientHttp2Session,
      ...args: unknown[]
    ) {
      openedOn.push({ closed: this.closed, destroyed: this.destroyed });
      return original.apply(this, args);
    };

    try {
      const retired = server.sessions.slice(0, POOL_SIZE / 2);
      const before = retired.map((session) =>
        server!.streamsBySession.get(session),
      );
      for (const session of retired)
        session.goaway(http2.constants.NGHTTP2_NO_ERROR);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const results = await Promise.all(
        Array.from({ length: POOL_SIZE * 2 }, () =>
          provider.sandbox.getById(SANDBOX_ID),
        ),
      );

      expect(results.every((result) => result?.sandboxId === SANDBOX_ID)).toBe(
        true,
      );
      expect(openedOn).toHaveLength(POOL_SIZE * 2);
      expect(openedOn.every((state) => !state.closed && !state.destroyed)).toBe(
        true,
      );
      // One stream per request means nothing was refused and resent, and the
      // retired sessions received no new streams.
      expect(
        retired.map((session) => server!.streamsBySession.get(session)),
      ).toEqual(before);
    } finally {
      prototype.request = original;
    }
  });

  it("should reconnect promptly after every pooled session received GOAWAY", async () => {
    server = await startServer(credentials);
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });
    await provider.sandbox.getById(SANDBOX_ID);
    await until(() => server!.sessions.length === POOL_SIZE);
    await new Promise((resolve) => setTimeout(resolve, 50));

    for (const session of server.sessions)
      session.goaway(http2.constants.NGHTTP2_NO_ERROR);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const started = Date.now();
    const sandbox = await provider.sandbox.getById(SANDBOX_ID);

    expect(sandbox?.sandboxId).toBe(SANDBOX_ID);
    expect(Date.now() - started).toBeLessThan(500);
    expect(server.sessions.length).toBeGreaterThan(POOL_SIZE);
  });

  it("should resend a create the server refused with REFUSED_STREAM", async () => {
    server = await startServer(credentials, {
      onStream: (stream, _headers, { streamIndex }) => {
        if (streamIndex === 0)
          stream.close(http2.constants.NGHTTP2_REFUSED_STREAM);
        else respondSandbox(stream, 201);
      },
    });
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });

    const sandbox = await provider.sandbox.create();

    expect(sandbox.sandboxId).toBe(SANDBOX_ID);
    expect(server.streamCount()).toBe(2);
  });

  it("should resend a create rejected by GOAWAY above its last-stream-id", async () => {
    const raw = await startRawGoawayServer(credentials);
    try {
      const provider = miosa({ apiKey: API_KEY, baseUrl: raw.baseUrl });

      const sandbox = await provider.sandbox.create();

      expect(sandbox.sandboxId).toBe(SANDBOX_ID);
      expect(raw.headersFrames()).toBe(2);
    } finally {
      await raw.close();
    }
  });

  it("should not resend a create the server may have processed", async () => {
    server = await startServer(credentials, {
      onStream: (stream) =>
        stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR),
    });
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });

    await expect(provider.sandbox.create()).rejects.toThrow();
    expect(server.streamCount()).toBe(1);
  });

  it("should resend an idempotent GET after a transport failure", async () => {
    server = await startServer(credentials, {
      onStream: (stream, _headers, { streamIndex }) => {
        if (streamIndex === 0)
          stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
        else respondSandbox(stream);
      },
    });
    const provider = miosa({ apiKey: API_KEY, baseUrl: server.baseUrl });

    const sandbox = await provider.sandbox.getById(SANDBOX_ID);

    expect(sandbox?.sandboxId).toBe(SANDBOX_ID);
    expect(server.streamCount()).toBe(2);
  });

  it("should fail promptly when no session can connect", async () => {
    const closed = net.createServer();
    await new Promise<void>((resolve) =>
      closed.listen(0, "127.0.0.1", resolve),
    );
    const { port } = closed.address() as net.AddressInfo;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const provider = miosa({
      apiKey: API_KEY,
      baseUrl: `https://127.0.0.1:${port}/api/v1`,
    });

    const started = Date.now();
    await expect(provider.sandbox.create()).rejects.toThrow(/ECONNREFUSED/);
    // The old gate always waited out its 1s first-ready timer here.
    expect(Date.now() - started).toBeLessThan(500);
  });
});
