-- Run this in: Supabase Dashboard → SQL Editor → New query

CREATE TABLE IF NOT EXISTS apps (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL,
  name        TEXT        NOT NULL,
  description TEXT,
  url         TEXT,
  api_key     TEXT        UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_apps_user_id  ON apps(user_id);
CREATE INDEX IF NOT EXISTS idx_apps_api_key  ON apps(api_key) WHERE api_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS sdk_device_sessions (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  device_code TEXT        NOT NULL UNIQUE,
  user_code   TEXT        NOT NULL,
  status      TEXT        NOT NULL DEFAULT 'pending',
  app_name    TEXT        NOT NULL,
  description TEXT,
  user_id     UUID,
  app_id      UUID,
  api_key     TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sdk_device_sessions_device_code
  ON sdk_device_sessions(device_code);
CREATE INDEX IF NOT EXISTS idx_sdk_device_sessions_status_expires
  ON sdk_device_sessions(status, expires_at);
