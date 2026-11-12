-- Esquema para Cloudflare D1 (SQLite) - Navidad 2026
CREATE TABLE IF NOT EXISTS users (
  username      TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','participant')),
  password_hash TEXT NOT NULL,
  daily_gifts   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS gifts (
  username  TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
  position  INTEGER NOT NULL CHECK (position BETWEEN 0 AND 2),
  detail    TEXT NOT NULL DEFAULT '',
  image_url TEXT NOT NULL DEFAULT '',
  buy_url   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (username, position)
);

-- Contador de versión: sube con cada cambio; los equipos lo consultan para saber si deben actualizarse
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta (key, value) VALUES ('version', 1);
