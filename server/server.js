import express from "express";
import helmet from "helmet";
import compression from "compression";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { nanoid } from "nanoid";
import { z } from "zod";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

const env = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 3000),
  jwtSecret: process.env.JWT_SECRET,
  adminUsername: process.env.ADMIN_USERNAME,
  adminPassword: process.env.ADMIN_PASSWORD,
  databasePath: process.env.DATABASE_PATH || "./data/luau.db",
  publicUrl: process.env.PUBLIC_URL || "http://localhost:3000",
  corsOrigin: process.env.CORS_ORIGIN || "",
  rawRequireToken: process.env.RAW_REQUIRE_TOKEN !== "false",
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m"
};

if (!env.jwtSecret || env.jwtSecret.length < 32) {
  if (env.nodeEnv === "production") {
    throw new Error("JWT_SECRET must contain at least 32 characters.");
  }

  console.warn("WARNING: JWT_SECRET is not configured securely.");
}

if (!env.adminUsername || !env.adminPassword) {
  if (env.nodeEnv === "production") {
    throw new Error("ADMIN_USERNAME and ADMIN_PASSWORD are required.");
  }
}

const dataDir = path.dirname(path.resolve(ROOT, env.databasePath));

fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.resolve(ROOT, env.databasePath));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scripts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS script_versions (
    id TEXT PRIMARY KEY,
    script_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    filename TEXT NOT NULL,
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(script_id) REFERENCES scripts(id) ON DELETE CASCADE,
    UNIQUE(script_id, version)
  );

  CREATE TABLE IF NOT EXISTS access_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    subject TEXT,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_versions_script
  ON script_versions(script_id, version DESC);

  CREATE INDEX IF NOT EXISTS idx_audit_created
  ON audit_logs(created_at DESC);
`);

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"]
      }
    },
    referrerPolicy: {
      policy: "no-referrer"
    }
  })
);

app.use(compression());

app.use(
  express.json({
    limit: "32kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "16kb"
  })
);

app.use(cookieParser());

if (env.corsOrigin) {
  app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin === env.corsOrigin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, X-CSRF-Token"
      );
      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS"
      );
    }

    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }

    next();
  });
}

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.API_RATE_LIMIT || 300),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "rate_limited"
  }
});

const rawLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RAW_RATE_LIMIT || 120),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "rate_limited"
  }
});

app.use("/api", apiLimiter);
app.use("/raw", rawLimiter);

function now() {
  return new Date().toISOString();
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function hashToken(token) {
  return sha256(token);
}

function safeEqual(a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

function audit(action, subject, req) {
  db.prepare(`
    INSERT INTO audit_logs
    (id, action, subject, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    nanoid(),
    action,
    subject || null,
    req.ip || null,
    String(req.headers["user-agent"] || "").slice(0, 512),
    now()
  );
}

function createJwt(payload) {
  return jwt.sign(payload, env.jwtSecret, {
    expiresIn: "2h",
    issuer: "luau-delivery",
    audience: "luau-delivery-admin"
  });
}

function authenticateAdmin(req, res, next) {
  const token = req.cookies.admin_session;

  if (!token) {
    return res.status(401).json({
      error: "authentication_required"
    });
  }

  try {
    req.admin = jwt.verify(token, env.jwtSecret, {
      issuer: "luau-delivery",
      audience: "luau-delivery-admin"
    });

    next();
  } catch {
    return res.status(401).json({
      error: "invalid_session"
    });
  }
}

function authenticateApiToken(requiredScope) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "authentication_required"
      });
    }

    const token = header.slice("Bearer ".length).trim();

    if (!token || token.length > 512) {
      return res.status(401).json({
        error: "invalid_token"
      });
    }

    const row = db
      .prepare(
        `
        SELECT *
        FROM access_tokens
        WHERE token_hash = ?
          AND revoked_at IS NULL
      `
      )
      .get(hashToken(token));

    if (!row) {
      return res.status(401).json({
        error: "invalid_token"
      });
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return res.status(401).json({
        error: "token_expired"
      });
    }

    let scopes;

    try {
      scopes = JSON.parse(row.scopes);
    } catch {
      return res.status(401).json({
        error: "invalid_token"
      });
    }

    if (!scopes.includes(requiredScope)) {
      return res.status(403).json({
        error: "insufficient_scope"
      });
    }

    req.apiToken = row;
    next();
  };
}

function requireRawAuthorization(req, res, next) {
  if (!env.rawRequireToken) {
    return next();
  }

  return authenticateApiToken("scripts:read")(req, res, next);
}

function validateId(req, res, next) {
  const schema = z.object({
    id: z.string().regex(/^[a-zA-Z0-9_-]{4,64}$/)
  });

  const result = schema.safeParse(req.params);

  if (!result.success) {
    return res.status(400).json({
      error: "invalid_script_id"
    });
  }

  next();
}

function scriptMetadata(script) {
  return {
    id: script.id,
    name: script.name,
    description: script.description,
    visibility: script.visibility,
    currentVersion: script.current_version,
    createdAt: script.created_at,
    updatedAt: script.updated_at
  };
}

app.get("/api/health", (_req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    status: "ok"
  });
});

/*
 * Authentication
 */

app.post("/api/auth/login", (req, res) => {
  const schema = z.object({
    username: z.string().min(1).max(128),
    password: z.string().min(1).max(512)
  });

  const parsed = schema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request"
    });
  }

  const { username, password } = parsed.data;

  if (
    !env.adminUsername ||
    username !== env.adminUsername ||
    !safeEqual(password, env.adminPassword || "")
  ) {
    audit("auth.login.failure", username, req);

    return res.status(401).json({
      error: "invalid_credentials"
    });
  }

  const session = createJwt({
    sub: username,
    role: "admin"
  });

  res.cookie("admin_session", session, {
    httpOnly: true,
    secure: env.nodeEnv === "production",
    sameSite: "strict",
    maxAge: 2 * 60 * 60 * 1000,
    path: "/"
  });

  audit("auth.login.success", username, req);

  res.json({
    authenticated: true
  });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("admin_session", {
    httpOnly: true,
    secure: env.nodeEnv === "production",
    sameSite: "strict",
    path: "/"
  });

  res.status(204).end();
});

app.get("/api/auth/me", authenticateAdmin, (req, res) => {
  res.json({
    authenticated: true,
    username: req.admin.sub,
    role: req.admin.role
  });
});

/*
 * Scripts
 */

app.get("/api/v1/scripts", (req, res) => {
  const rows = db
    .prepare(
      `
      SELECT *
      FROM scripts
      WHERE visibility = 'public'
      ORDER BY updated_at DESC
    `
    )
    .all();

  res.set("Cache-Control", "public, max-age=30, stale-while-revalidate=60");

  res.json({
    scripts: rows.map(scriptMetadata)
  });
});

app.get(
  "/api/v1/scripts/:id",
  validateId,
  requireRawAuthorization,
  (req, res) => {
    const script = db
      .prepare(
        `
        SELECT *
        FROM scripts
        WHERE id = ?
      `
      )
      .get(req.params.id);

    if (!script) {
      return res.status(404).json({
        error: "script_not_found"
      });
    }

    const version = db
      .prepare(
        `
        SELECT
          id,
          version,
          filename,
          sha256,
          byte_size,
          created_at
        FROM script_versions
        WHERE script_id = ?
          AND version = ?
      `
      )
      .get(script.id, script.current_version);

    res.set(
      "Cache-Control",
      script.visibility === "public"
        ? "public, max-age=30"
        : "private, no-store"
    );

    res.json({
      script: scriptMetadata(script),
      currentVersion: version || null
    });
  }
);

app.get(
  "/api/v1/scripts/:id/raw",
  validateId,
  rawLimiter,
  requireRawAuthorization,
  (req, res) => {
    const versionSchema = z.object({
      version: z.coerce.number().int().positive().optional()
    });

    const parsed = versionSchema.safeParse(req.query);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_version"
      });
    }

    const script = db
      .prepare(
        `
        SELECT *
        FROM scripts
        WHERE id = ?
      `
      )
      .get(req.params.id);

    if (!script) {
      return res.status(404).json({
        error: "script_not_found"
      });
    }

    const versionNumber =
      parsed.data.version || script.current_version;

    const version = db
      .prepare(
        `
        SELECT *
        FROM script_versions
        WHERE script_id = ?
          AND version = ?
      `
      )
      .get(script.id, versionNumber);

    if (!version) {
      return res.status(404).json({
        error: "version_not_found"
      });
    }

    audit(
      "script.raw.read",
      `${script.id}@${version.version}`,
      req
    );

    /*
     * IMPORTANT:
     * Do not add metadata, JSON, HTML, debug information,
     * filesystem paths, repository information, etc.
     *
     * The response body is ONLY the Luau source.
     */

    res.status(200);

    res.set("Content-Type", "text/plain; charset=utf-8");
    res.set("X-Content-Type-Options", "nosniff");
    res.set(
      "Cache-Control",
      script.visibility === "public"
        ? "public, max-age=60, s-maxage=60"
        : "private, no-store"
    );
    res.set("Content-Length", Buffer.byteLength(version.source));

    return res.send(version.source);
  }
);

app.get(
  "/api/v1/scripts/:id/versions",
  validateId,
  requireRawAuthorization,
  (req, res) => {
    const script = db
      .prepare("SELECT * FROM scripts WHERE id = ?")
      .get(req.params.id);

    if (!script) {
      return res.status(404).json({
        error: "script_not_found"
      });
    }

    const versions = db
      .prepare(
        `
        SELECT
          version,
          filename,
          sha256,
          byte_size,
          created_at
        FROM script_versions
        WHERE script_id = ?
        ORDER BY version DESC
      `
      )
      .all(script.id);

    res.json({
      scriptId: script.id,
      versions
    });
  }
);

/*
 * Admin script creation.
 */

app.post(
  "/api/admin/scripts",
  authenticateAdmin,
  (req, res) => {
    const schema = z.object({
      id: z
        .string()
        .regex(/^[a-zA-Z0-9_-]{4,64}$/),
      name: z.string().min(1).max(128),
      description: z.string().max(1000).default(""),
      filename: z
        .string()
        .regex(/^[a-zA-Z0-9_.-]+\.(lua|luau)$/),
      source: z.string().min(1).max(1024 * 1024),
      visibility: z.enum(["public", "private"]).default("private")
    });

    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const data = parsed.data;

    const existing = db
      .prepare("SELECT id FROM scripts WHERE id = ?")
      .get(data.id);

    if (existing) {
      return res.status(409).json({
        error: "script_exists"
      });
    }

    const timestamp = now();
    const versionId = nanoid();
    const hash = sha256(data.source);

    const transaction = db.transaction(() => {
      db.prepare(
        `
        INSERT INTO scripts
        (id, name, description, visibility, current_version, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
      `
      ).run(
        data.id,
        data.name,
        data.description,
        data.visibility,
        timestamp,
        timestamp
      );

      db.prepare(
        `
        INSERT INTO script_versions
        (id, script_id, version, filename, source, sha256, byte_size, created_at)
        VALUES (?, ?, 1, ?, ?, ?, ?, ?)
      `
      ).run(
        versionId,
        data.id,
        data.filename,
        data.source,
        hash,
        Buffer.byteLength(data.source),
        timestamp
      );
    });

    transaction();

    audit("script.create", data.id, req);

    res.status(201).json({
      script: {
        id: data.id,
        version: 1,
        sha256: hash
      }
    });
  }
);

app.post(
  "/api/admin/scripts/:id/versions",
  authenticateAdmin,
  validateId,
  (req, res) => {
    const schema = z.object({
      filename: z
        .string()
        .regex(/^[a-zA-Z0-9_.-]+\.(lua|luau)$/),
      source: z.string().min(1).max(1024 * 1024)
    });

    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_request",
        details: parsed.error.flatten()
      });
    }

    const script = db
      .prepare("SELECT * FROM scripts WHERE id = ?")
      .get(req.params.id);

    if (!script) {
      return res.status(404).json({
        error: "script_not_found"
      });
    }

    const version = script.current_version + 1;
    const timestamp = now();
    const hash = sha256(parsed.data.source);

    db.transaction(() => {
      db.prepare(
        `
        INSERT INTO script_versions
        (id, script_id, version, filename, source, sha256, byte_size, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `
      ).run(
        nanoid(),
        script.id,
        version,
        parsed.data.filename,
        parsed.data.source,
        hash,
        Buffer.byteLength(parsed.data.source),
        timestamp
      );

      db.prepare(
        `
        UPDATE scripts
        SET current_version = ?, updated_at = ?
        WHERE id = ?
      `
      ).run(version, timestamp, script.id);
    })();

    audit(
      "script.version.create",
      `${script.id}@${version}`,
      req
    );

    res.status(201).json({
      scriptId: script.id,
      version,
      sha256: hash
    });
  }
);

/*
 * Access tokens.
 *
 * The plaintext token is returned exactly once.
 * Only its SHA-256 hash is stored.
 */

app.post(
  "/api/admin/tokens",
  authenticateAdmin,
  (req, res) => {
    const schema = z.object({
      name: z.string().min(1).max(128),
      scopes: z
        .array(z.enum(["scripts:read"]))
        .min(1),
      expiresInSeconds: z
        .number()
        .int()
        .min(60)
        .max(60 * 60 * 24 * 30)
    });

    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_request"
      });
    }

    const token = `lud_${nanoid(48)}`;
    const expiresAt = new Date(
      Date.now() + parsed.data.expiresInSeconds * 1000
    ).toISOString();

    db.prepare(
      `
      INSERT INTO access_tokens
      (id, token_hash, name, scopes, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `
    ).run(
      nanoid(),
      hashToken(token),
      parsed.data.name,
      JSON.stringify(parsed.data.scopes),
      expiresAt,
      now()
    );

    audit("token.create", parsed.data.name, req);

    res.status(201).json({
      token,
      expiresAt,
      scopes: parsed.data.scopes
    });
  }
);

app.delete(
  "/api/admin/tokens/:id",
  authenticateAdmin,
  (req, res) => {
    const result = db
      .prepare(
        `
        UPDATE access_tokens
        SET revoked_at = ?
        WHERE id = ?
          AND revoked_at IS NULL
      `
      )
      .run(now(), req.params.id);

    if (result.changes === 0) {
      return res.status(404).json({
        error: "token_not_found"
      });
    }

    audit("token.revoke", req.params.id, req);

    res.status(204).end();
  }
);

/*
 * Human-readable raw route.
 *
 * This intentionally has no HTML wrapping.
 */

app.get(
  "/raw/:id",
  validateId,
  rawLimiter,
  requireRawAuthorization,
  (req, res) => {
    const script = db
      .prepare("SELECT current_version FROM scripts WHERE id = ?")
      .get(req.params.id);

    if (!script) {
      return res.status(404).type("text").send("Script not found.");
    }

    const version = db
      .prepare(
        `
        SELECT source
        FROM script_versions
        WHERE script_id = ?
          AND version = ?
      `
      )
      .get(req.params.id, script.current_version);

    if (!version) {
      return res.status(404).type("text").send("Script not found.");
    }

    res.set("Content-Type", "text/plain; charset=utf-8");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Cache-Control", "private, no-store");

    return res.send(version.source);
  }
);

/*
 * Static frontend.
 */

app.use(
  express.static(path.join(ROOT, "public"), {
    etag: true,
    maxAge: env.nodeEnv === "production" ? "1h" : 0,
    extensions: ["html"]
  })
);

app.get("*splat", (_req, res) => {
  res.sendFile(path.join(ROOT, "public", "index.html"));
});

/*
 * Sanitized error handler.
 */

app.use((err, _req, res, _next) => {
  console.error(err);

  if (res.headersSent) {
    return;
  }

  res.status(500).json({
    error: "internal_server_error"
  });
});

if (process.argv.includes("--validate-luau")) {
  const scriptsDir = path.join(ROOT, "scripts");

  const files = fs
    .readdirSync(scriptsDir)
    .filter((file) => /\.(lua|luau)$/i.test(file));

  let invalid = false;

  for (const file of files) {
    const source = fs.readFileSync(
      path.join(scriptsDir, file),
      "utf8"
    );

    if (source.includes("\0")) {
      console.error(`Invalid NUL byte: ${file}`);
      invalid = true;
    }

    if (Buffer.byteLength(source) > 1024 * 1024) {
      console.error(`File exceeds 1 MB: ${file}`);
      invalid = true;
    }

    console.log(`Validated: ${file}`);
  }

  process.exit(invalid ? 1 : 0);
}

if (!process.argv.includes("--test-mode")) {
  app.listen(env.port, () => {
    console.log(
      `Luau Delivery listening on ${env.publicUrl}`
    );
  });
}

export { app, db };
