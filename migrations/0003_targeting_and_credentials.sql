ALTER TABLE devices ADD COLUMN language TEXT;
ALTER TABLE devices ADD COLUMN user_id TEXT;
ALTER TABLE devices ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';

UPDATE users
SET role = 'admin', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE role = 'owner'
  AND id NOT IN (
    SELECT id FROM users WHERE role = 'owner' ORDER BY created_at ASC, id ASC LIMIT 1
  );

CREATE UNIQUE INDEX IF NOT EXISTS users_single_owner_idx ON users(role) WHERE role = 'owner';

CREATE INDEX IF NOT EXISTS devices_app_language_idx ON devices(app_id, environment, status, language);
CREATE INDEX IF NOT EXISTS devices_app_user_idx ON devices(app_id, environment, status, user_id);

ALTER TABLE apns_credentials ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'
  CHECK (environment IN ('development', 'production'));
ALTER TABLE apns_credentials ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0;

UPDATE apns_credentials
SET is_default = 1
WHERE id IN (
  SELECT credential.id
  FROM apns_credentials AS credential
  WHERE credential.updated_at = (
    SELECT MAX(candidate.updated_at)
    FROM apns_credentials AS candidate
    WHERE candidate.app_id = credential.app_id
      AND candidate.environment = credential.environment
  )
);

CREATE INDEX IF NOT EXISTS apns_credentials_app_environment_idx
  ON apns_credentials(app_id, environment, is_default, updated_at);
