-- ============================================
-- SUPABASE MAXIMUM INSECURE TEST SETUP
-- NUR FÜR TESTZWECKE - NICHT IN PRODUKTION!
-- ============================================

-- =====================
-- 1. UNSICHERE TABELLEN
-- =====================

-- Test-Tabelle mit "geheimen" Daten
CREATE TABLE public.test_secrets (
  id SERIAL PRIMARY KEY,
  secret_name TEXT,
  secret_value TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.test_secrets (secret_name, secret_value) VALUES
  ('api_key', 'sk-test-12345'),
  ('database_password', 'supersecret123'),
  ('admin_token', 'admin-token-xyz'),
  ('stripe_key', 'sk_live_fake123456'),
  ('jwt_secret', 'my-super-secret-jwt-key');

-- User-Tabelle mit sensiblen Daten
CREATE TABLE public.users_exposed (
  id SERIAL PRIMARY KEY,
  email TEXT,
  password_hash TEXT,
  phone TEXT,
  credit_card_last4 TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.users_exposed (email, password_hash, phone, credit_card_last4) VALUES
  ('admin@test.com', '$2b$10$fakehash123', '+49123456789', '4242'),
  ('user@test.com', '$2b$10$fakehash456', '+49987654321', '1234'),
  ('vip@test.com', '$2b$10$fakehash789', '+49111222333', '5678');

-- Config-Tabelle
CREATE TABLE public.app_config (
  id SERIAL PRIMARY KEY,
  key TEXT,
  value TEXT
);

INSERT INTO public.app_config (key, value) VALUES
  ('feature_flags', '{"premium": true, "beta": true}'),
  ('api_endpoints', '{"internal": "https://internal-api.com"}'),
  ('admin_emails', '["admin@company.com", "ceo@company.com"]');

-- =====================
-- 2. RLS KOMPLETT OFFEN
-- =====================

-- Alle Tabellen: RLS an aber Policy erlaubt ALLES für anon
ALTER TABLE public.test_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users_exposed ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_config ENABLE ROW LEVEL SECURITY;

-- UNSICHER: Anonymer Vollzugriff auf alle Tabellen
CREATE POLICY "anon_full_access_secrets" ON public.test_secrets FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon_full_access_users" ON public.users_exposed FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon_full_access_config" ON public.app_config FOR ALL TO anon USING (true) WITH CHECK (true);

-- =====================
-- 3. UNSICHERE STORAGE
-- =====================

-- Öffentliche Buckets erstellen
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES
  ('public-uploads', 'public-uploads', true, 52428800, NULL),
  ('user-documents', 'user-documents', true, 52428800, NULL),
  ('backups', 'backups', true, 104857600, NULL);

-- Storage Policies: Erlaube ALLES für anon
CREATE POLICY "anon_storage_all_public" ON storage.objects FOR ALL TO anon USING (bucket_id = 'public-uploads') WITH CHECK (bucket_id = 'public-uploads');
CREATE POLICY "anon_storage_all_docs" ON storage.objects FOR ALL TO anon USING (bucket_id = 'user-documents') WITH CHECK (bucket_id = 'user-documents');
CREATE POLICY "anon_storage_all_backups" ON storage.objects FOR ALL TO anon USING (bucket_id = 'backups') WITH CHECK (bucket_id = 'backups');

-- =====================
-- 4. UNSICHERE FUNKTIONEN
-- =====================

-- Funktion die alle User-Daten zurückgibt
CREATE OR REPLACE FUNCTION public.get_all_users()
RETURNS SETOF public.users_exposed
LANGUAGE sql
SECURITY DEFINER
AS $$
  SELECT * FROM public.users_exposed;
$$;

-- Funktion die Secrets zurückgibt
CREATE OR REPLACE FUNCTION public.get_secrets()
RETURNS SETOF public.test_secrets
LANGUAGE sql
SECURITY DEFINER
AS $$
  SELECT * FROM public.test_secrets;
$$;

-- Grants für anon
GRANT EXECUTE ON FUNCTION public.get_all_users() TO anon;
GRANT EXECUTE ON FUNCTION public.get_secrets() TO anon;

-- ============================================
-- FERTIG! Dieses Setup ist MAXIMAL UNSICHER:
-- - Alle Tabellen lesbar/schreibbar für anon
-- - Storage Buckets öffentlich
-- - RPC Funktionen für anon zugänglich
-- ============================================
