-- Lovable Squares shared database (Cloudflare D1)
-- Apply with:  npx wrangler d1 execute lovable-squares --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS members (
  id      TEXT PRIMARY KEY,
  user    TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name    TEXT NOT NULL,
  role    TEXT NOT NULL,                -- administrator | treasurer | member
  owner   INTEGER NOT NULL DEFAULT 0,   -- group owner: always an administrator, can't be deleted
  salt    TEXT NOT NULL,
  pw      TEXT NOT NULL,                -- PBKDF2 of the browser's SHA-256 of the password
  created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token     TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  expires   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_member ON sessions(member_id);

CREATE TABLE IF NOT EXISTS squares (
  id       TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  label    TEXT NOT NULL,
  mime     TEXT NOT NULL,
  data     TEXT NOT NULL,               -- base64 image (a cut-out square is ~20-40 KB)
  shared   INTEGER NOT NULL DEFAULT 0,  -- 1 = in the group library for everyone
  created  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS squares_owner ON squares(owner_id);
CREATE INDEX IF NOT EXISTS squares_shared ON squares(shared);
