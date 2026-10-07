// Lovable Squares API — Cloudflare Worker + D1.
// Logins and members are shared across every device, and so are squares:
// each member has their own squares and can share any of them with the group.
//
// The browser never sends the plain password: it sends SHA-256(password) (as the
// site always has), and here that is salted and stretched with PBKDF2 before storing.

const PBKDF2_ITERATIONS = 10000;          // free-plan CPU budget is ~10 ms per request
const SESSION_DAYS = 90;
const MAX_IMAGE_BYTES = 600 * 1024;
const ROLES = ["administrator", "treasurer", "member"];

// Day-one accounts: same usernames, passwords and fixed ids as the site's seed.
const SEED_MEMBERS = [
  { id: "m-rosslyn",  user: "rosslyn",  name: "Rosslyn",  role: "administrator", owner: 1, hash: "474c9e3abf4a2a93abd2ab9015ca8c7b3cd6483ae331b48ae8db14379b2c2830" },
  { id: "m-felicity", user: "felicity", name: "Felicity", role: "administrator", owner: 0, hash: "288a6f803a5f968ed8db32a7fc62ab42aba3fb1b8860fef4e779ecbfd7608470" },
  { id: "m-june",     user: "june",     name: "June",     role: "treasurer",     owner: 0, hash: "cb1b1cb9ae183e57f0db43a69b8f36620d0cc292990897078ac6de59eaa9d672" },
  { id: "m-kezza",    user: "kezza",    name: "Kezza",    role: "member",        owner: 0, hash: "cb1b1cb9ae183e57f0db43a69b8f36620d0cc292990897078ac6de59eaa9d672" },
];

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      const res = await route(req, env);
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 500) console.error(e && e.stack || e);
      return json({ error: status === 500 ? "Something went wrong on the server." : e.message }, status, cors);
    }
  },
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new HttpError(status, message); };

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const h = { "Vary": "Origin" };
  if (allowed.includes(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });
}

async function body(req) {
  try { return await req.json(); } catch (e) { fail(400, "Bad request."); }
}

async function route(req, env) {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "");
  const m = req.method;
  let mt;

  // Square images are public by unguessable id so <img> / canvas can load them.
  if (m === "GET" && (mt = p.match(/^\/img\/([\w-]+)$/))) return image(env, mt[1]);

  await ensureSeed(env);

  if (m === "POST" && p === "/api/login") return login(req, env);
  if (m === "POST" && p === "/api/logout") return logout(req, env);
  if (m === "GET" && p === "/api/me") return json({ me: publicMember(await requireMember(req, env)) });

  if (m === "GET" && p === "/api/members") { await requireMember(req, env); return listMembers(env); }
  if (m === "POST" && p === "/api/members") return addMember(req, env, await requireAdmin(req, env));
  if ((mt = p.match(/^\/api\/members\/([\w-]+)$/))) {
    if (m === "PATCH") return updateMember(req, env, await requireAdmin(req, env), mt[1]);
    if (m === "DELETE") return deleteMember(env, await requireAdmin(req, env), mt[1]);
  }

  if (m === "GET" && p === "/api/squares") return listSquares(env, await optionalMember(req, env));
  if (m === "POST" && p === "/api/squares") return addSquare(req, env, await requireMember(req, env));
  if ((mt = p.match(/^\/api\/squares\/([\w-]+)$/))) {
    if (m === "PATCH") return updateSquare(req, env, await requireMember(req, env), mt[1]);
    if (m === "DELETE") return deleteSquare(env, await requireMember(req, env), mt[1]);
  }

  fail(404, "Not found.");
}

/* ---------------- passwords & sessions ---------------- */

function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }
function randomHex(bytes) { return hex(crypto.getRandomValues(new Uint8Array(bytes))); }
function newId(prefix) { return prefix + "-" + randomHex(8); }

async function stretch(clientHash, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(clientHash), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITERATIONS }, key, 256);
  return hex(bits);
}

function sameString(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function validHash(h) { return typeof h === "string" && /^[0-9a-f]{64}$/.test(h); }

let seeded = false;
async function ensureSeed(env) {
  if (seeded) return;
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM members").first();
  if (row.n === 0) {
    const now = Date.now();
    const stmts = [];
    for (const s of SEED_MEMBERS) {
      const salt = randomHex(16);
      stmts.push(env.DB.prepare(
        "INSERT OR IGNORE INTO members (id, user, name, role, owner, salt, pw, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(s.id, s.user, s.name, s.role, s.owner, salt, await stretch(s.hash, salt), now));
    }
    await env.DB.batch(stmts);
  }
  seeded = true;
}

async function login(req, env) {
  const { user, hash } = await body(req);
  if (typeof user !== "string" || !validHash(hash)) fail(400, "Please enter your username and password.");
  const m = await env.DB.prepare("SELECT * FROM members WHERE user = ?").bind(user.trim()).first();
  // Same message either way so usernames can't be probed
  if (!m || !sameString(await stretch(hash, m.salt), m.pw)) fail(401, "Sorry, that username or password wasn't recognised.");
  const token = randomHex(32);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(now),
    env.DB.prepare("INSERT INTO sessions (token, member_id, expires) VALUES (?, ?, ?)")
      .bind(token, m.id, now + SESSION_DAYS * 864e5),
  ]);
  return json({ token, me: publicMember(m) });
}

async function logout(req, env) {
  const t = bearer(req);
  if (t) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
  return json({ ok: true });
}

function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

async function optionalMember(req, env) {
  const t = bearer(req);
  if (!t) return null;
  return await env.DB.prepare(
    "SELECT m.* FROM sessions s JOIN members m ON m.id = s.member_id WHERE s.token = ? AND s.expires > ?"
  ).bind(t, Date.now()).first();
}
async function requireMember(req, env) {
  const m = await optionalMember(req, env);
  if (!m) fail(401, "Please log in again.");
  return m;
}
async function requireAdmin(req, env) {
  const m = await requireMember(req, env);
  if (m.role !== "administrator") fail(403, "Only an administrator can do that.");
  return m;
}

/* ---------------- members ---------------- */

function publicMember(m) {
  return { id: m.id, user: m.user, name: m.name, role: m.role, owner: !!m.owner };
}

async function listMembers(env) {
  const { results } = await env.DB.prepare("SELECT * FROM members ORDER BY owner DESC, created, name").all();
  return json({ members: results.map(publicMember) });
}

async function adminCount(env) {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE role = 'administrator'").first()).n;
}

async function addMember(req, env) {
  const { name, user, hash, role } = await body(req);
  const n = String(name || "").trim(), u = String(user || "").trim().toLowerCase();
  if (!n || !u || !validHash(hash)) fail(400, "Please enter a full name, username and password.");
  if (!/^[a-z0-9._-]{2,32}$/.test(u)) fail(400, "Usernames can use letters, numbers, dots and dashes only.");
  if (!ROLES.includes(role)) fail(400, "Unknown role.");
  const taken = await env.DB.prepare("SELECT 1 FROM members WHERE user = ?").bind(u).first();
  if (taken) fail(409, "That username is already taken.");
  const salt = randomHex(16);
  const m = { id: newId("m"), user: u, name: n.slice(0, 60), role, owner: 0 };
  await env.DB.prepare(
    "INSERT INTO members (id, user, name, role, owner, salt, pw, created) VALUES (?, ?, ?, ?, 0, ?, ?, ?)"
  ).bind(m.id, m.user, m.name, m.role, salt, await stretch(hash, salt), Date.now()).run();
  return json({ member: publicMember(m) }, 201);
}

async function updateMember(req, env, admin, id) {
  const m = await env.DB.prepare("SELECT * FROM members WHERE id = ?").bind(id).first();
  if (!m) fail(404, "That member no longer exists.");
  const { role, hash } = await body(req);
  if (role !== undefined && role !== m.role) {
    if (!ROLES.includes(role)) fail(400, "Unknown role.");
    if (m.owner) fail(400, "The group owner is always an administrator.");
    if (m.role === "administrator" && (await adminCount(env)) <= 1) fail(400, "There must be at least one administrator.");
    await env.DB.prepare("UPDATE members SET role = ? WHERE id = ?").bind(role, id).run();
  }
  if (hash !== undefined) {
    if (!validHash(hash)) fail(400, "Password can't be empty.");
    const salt = randomHex(16);
    await env.DB.batch([
      env.DB.prepare("UPDATE members SET salt = ?, pw = ? WHERE id = ?").bind(salt, await stretch(hash, salt), id),
      // a new password signs them out everywhere else
      env.DB.prepare("DELETE FROM sessions WHERE member_id = ? AND member_id <> ?").bind(id, admin.id),
    ]);
  }
  const fresh = await env.DB.prepare("SELECT * FROM members WHERE id = ?").bind(id).first();
  return json({ member: publicMember(fresh) });
}

async function deleteMember(env, admin, id) {
  const m = await env.DB.prepare("SELECT * FROM members WHERE id = ?").bind(id).first();
  if (!m) return json({ ok: true });
  if (m.owner) fail(400, "The group owner's account can't be deleted.");
  if (m.id === admin.id) fail(400, "You can't delete your own account while you're signed in.");
  if (m.role === "administrator" && (await adminCount(env)) <= 1) fail(400, "There must be at least one administrator.");
  // Their private squares go; anything they shared stays in the group library.
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE member_id = ?").bind(id),
    env.DB.prepare("DELETE FROM squares WHERE owner_id = ? AND shared = 0").bind(id),
    env.DB.prepare("DELETE FROM members WHERE id = ?").bind(id),
  ]);
  return json({ ok: true });
}

/* ---------------- squares ---------------- */

function squareOut(s, me) {
  return {
    id: s.id, label: s.label, shared: !!s.shared,
    ownerId: s.owner_id, ownerName: s.owner_name || "a former member",
    mine: !!me && s.owner_id === me.id,
  };
}

async function listSquares(env, me) {
  const sel = "SELECT s.id, s.label, s.shared, s.owner_id, s.created, m.name AS owner_name FROM squares s LEFT JOIN members m ON m.id = s.owner_id";
  const group = (await env.DB.prepare(sel + " WHERE s.shared = 1 ORDER BY s.created").all()).results;
  const mine = me
    ? (await env.DB.prepare(sel + " WHERE s.owner_id = ? ORDER BY s.created").bind(me.id).all()).results
    : [];
  return json({ me: me ? publicMember(me) : null, group: group.map(s => squareOut(s, me)), mine: mine.map(s => squareOut(s, me)) });
}

async function addSquare(req, env, me) {
  const { label, data, shared } = await body(req);
  const mt = typeof data === "string" && data.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/);
  if (!mt) fail(400, "That doesn't look like a picture.");
  if (mt[2].length * 0.75 > MAX_IMAGE_BYTES) fail(413, "That picture is too big.");
  const s = {
    id: newId("sq"), owner_id: me.id, label: String(label || "My square").trim().slice(0, 40) || "My square",
    shared: shared ? 1 : 0, created: Date.now(), owner_name: me.name,
  };
  await env.DB.prepare(
    "INSERT INTO squares (id, owner_id, label, mime, data, shared, created) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(s.id, s.owner_id, s.label, mt[1], mt[2], s.shared, s.created).run();
  return json({ square: squareOut(s, me) }, 201);
}

async function updateSquare(req, env, me, id) {
  const s = await env.DB.prepare("SELECT id, owner_id, label, shared, created FROM squares WHERE id = ?").bind(id).first();
  if (!s) fail(404, "That square no longer exists.");
  const { label, shared } = await body(req);
  const isOwner = s.owner_id === me.id, isAdmin = me.role === "administrator";
  if (label !== undefined) {
    if (!isOwner) fail(403, "Only the person who added a square can rename it.");
    const l = String(label).trim().slice(0, 40);
    if (!l) fail(400, "Please give the square a name.");
    await env.DB.prepare("UPDATE squares SET label = ? WHERE id = ?").bind(l, id).run();
  }
  if (shared !== undefined) {
    // owners share/unshare their own; administrators may take anything out of the group library
    if (!isOwner && !(isAdmin && !shared)) fail(403, "Only the person who added a square can share it.");
    await env.DB.prepare("UPDATE squares SET shared = ? WHERE id = ?").bind(shared ? 1 : 0, id).run();
  }
  const fresh = await env.DB.prepare(
    "SELECT s.id, s.label, s.shared, s.owner_id, s.created, m.name AS owner_name FROM squares s LEFT JOIN members m ON m.id = s.owner_id WHERE s.id = ?"
  ).bind(id).first();
  return json({ square: squareOut(fresh, me) });
}

async function deleteSquare(env, me, id) {
  const s = await env.DB.prepare("SELECT owner_id FROM squares WHERE id = ?").bind(id).first();
  if (!s) return json({ ok: true });
  if (s.owner_id !== me.id) fail(403, "Only the person who added a square can delete it.");
  await env.DB.prepare("DELETE FROM squares WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

async function image(env, id) {
  const s = await env.DB.prepare("SELECT mime, data FROM squares WHERE id = ?").bind(id).first();
  if (!s) return new Response("Not found", { status: 404, headers: { "Access-Control-Allow-Origin": "*" } });
  const bin = Uint8Array.from(atob(s.data), c => c.charCodeAt(0));
  return new Response(bin, {
    headers: {
      "Content-Type": s.mime,
      // a square's picture never changes (renaming doesn't touch it)
      "Cache-Control": "public, max-age=31536000, immutable",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
