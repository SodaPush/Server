CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS registration_keys (
  id TEXT PRIMARY KEY NOT NULL,
  app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL UNIQUE,
  secret_ciphertext TEXT NOT NULL,
  secret_nonce TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS registration_keys_app_idx ON registration_keys(app_id, active);

CREATE TABLE IF NOT EXISTS devices (
  app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  installation_id TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('development', 'production')),
  device_token_ciphertext TEXT NOT NULL,
  device_token_nonce TEXT NOT NULL,
  device_token_hash TEXT NOT NULL,
  platform TEXT NOT NULL,
  app_version TEXT,
  app_build TEXT,
  locale TEXT,
  time_zone TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (app_id, installation_id, environment),
  UNIQUE (app_id, environment, device_token_hash)
);

CREATE INDEX IF NOT EXISTS devices_app_status_idx ON devices(app_id, environment, status);

CREATE TABLE IF NOT EXISTS replay_nonces (
  nonce TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS replay_nonces_expiry_idx ON replay_nonces(expires_at);
