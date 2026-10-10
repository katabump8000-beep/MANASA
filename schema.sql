CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  name_key TEXT NOT NULL UNIQUE,
  project_type TEXT NOT NULL CHECK (project_type IN ('telegram','whatsapp','nodejs')),
  entry_file TEXT NOT NULL DEFAULT 'index.js',
  ram_mb INTEGER NOT NULL DEFAULT 1024 CHECK (ram_mb BETWEEN 128 AND 65536),
  storage_mb INTEGER NOT NULL DEFAULT 2048 CHECK (storage_mb BETWEEN 128 AND 1048576),
  cpu_target_percent INTEGER NOT NULL DEFAULT 25 CHECK (cpu_target_percent BETWEEN 1 AND 100),
  runtime_provider TEXT,
  runtime_project_id TEXT,
  runtime_status TEXT NOT NULL DEFAULT 'not_configured' CHECK (runtime_status IN ('not_configured','stopped','starting','running','failed','unknown')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS projects_created_at_idx ON projects(created_at DESC);
