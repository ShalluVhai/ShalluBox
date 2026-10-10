-- ==============================================================================
-- ShalluBox Complete Supabase Setup & Master PIN (8520) Bypass
-- Run this in your Supabase Dashboard -> SQL Editor (New query -> Run)
-- Project: uobrhvazahlafsgtbxkv
-- ==============================================================================

-- 1. Enable pgcrypto extension for secure hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Create the files metadata table
CREATE TABLE IF NOT EXISTS public.files (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  pin_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  download_count INT DEFAULT 0
);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.files ENABLE ROW LEVEL SECURITY;

-- 4. Policy: Allow public to SELECT active (non-expired) files (24h retention)
DROP POLICY IF EXISTS "Allow public read active files" ON public.files;
CREATE POLICY "Allow public read active files" ON public.files
  FOR SELECT
  USING (expires_at > (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT);

-- 5. Policy: Allow public to INSERT new files (up to 50MB)
DROP POLICY IF EXISTS "Allow public insert files" ON public.files;
CREATE POLICY "Allow public insert files" ON public.files
  FOR INSERT
  WITH CHECK (true);

-- 6. Policy: Allow public to UPDATE download counts
DROP POLICY IF EXISTS "Allow public update download count" ON public.files;
CREATE POLICY "Allow public update download count" ON public.files
  FOR UPDATE
  USING (true);

-- 7. Policy: Allow public to DELETE files from the database
DROP POLICY IF EXISTS "Allow public delete files" ON public.files;
CREATE POLICY "Allow public delete files" ON public.files
  FOR DELETE
  USING (true);

-- 8. Storage bucket setup: create "shallubox-files" bucket (if not existing)
INSERT INTO storage.buckets (id, name, public)
VALUES ('shallubox-files', 'shallubox-files', true)
ON CONFLICT (id) DO NOTHING;

-- 9. Storage Policy: Allow public to upload into bucket
DROP POLICY IF EXISTS "Allow public storage upload" ON storage.objects;
CREATE POLICY "Allow public storage upload" ON storage.objects
  FOR INSERT
  WITH CHECK (bucket_id = 'shallubox-files');

-- 10. Storage Policy: Allow public to read / download from bucket
DROP POLICY IF EXISTS "Allow public storage read" ON storage.objects;
CREATE POLICY "Allow public storage read" ON storage.objects
  FOR SELECT
  USING (bucket_id = 'shallubox-files');

-- 11. Storage Policy: Allow public to DELETE files from bucket to free up space
DROP POLICY IF EXISTS "Allow public storage delete" ON storage.objects;
CREATE POLICY "Allow public storage delete" ON storage.objects
  FOR DELETE
  USING (bucket_id = 'shallubox-files');

-- 12. MASTER PIN (8520) BYPASS FUNCTION
-- Runs with admin privileges (SECURITY DEFINER) to delete the file row & storage object
CREATE OR REPLACE FUNCTION public.delete_file_with_master_pin(p_file_id TEXT, p_pin TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_file RECORD;
  v_computed_hash TEXT;
  v_is_master BOOLEAN;
BEGIN
  -- 1. Find the file in database
  SELECT * INTO v_file FROM public.files WHERE id = p_file_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'File not found');
  END IF;

  -- 2. Check if Secret Master PIN (8520) was entered
  v_is_master := (p_pin = '8520');

  -- 3. If not master PIN, verify SHA-256 hash using salt
  IF NOT v_is_master THEN
    v_computed_hash := encode(digest(p_pin || v_file.salt, 'sha256'), 'hex');
    IF v_computed_hash <> v_file.pin_hash THEN
      RETURN jsonb_build_object('success', false, 'error', 'Incorrect PIN');
    END IF;
  END IF;

  -- 4. Delete the physical object from storage bucket to free up space
  IF v_file.storage_path IS NOT NULL AND v_file.storage_path <> '' THEN
    DELETE FROM storage.objects 
    WHERE bucket_id = 'shallubox-files' AND name = v_file.storage_path;
  END IF;

  -- 5. Delete the database row
  DELETE FROM public.files WHERE id = p_file_id;

  RETURN jsonb_build_object(
    'success', true, 
    'message', 'File deleted successfully', 
    'storage_path', v_file.storage_path
  );
END;
$$;

-- Grant execution permission to public users
GRANT EXECUTE ON FUNCTION public.delete_file_with_master_pin(TEXT, TEXT) TO anon, authenticated;

-- 13. Helper procedure: Purge all expired files older than 24 hours
CREATE OR REPLACE FUNCTION public.purge_expired_shallubox_files()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Delete physical storage objects for expired files
  DELETE FROM storage.objects
  WHERE bucket_id = 'shallubox-files'
    AND name IN (
      SELECT storage_path FROM public.files 
      WHERE expires_at <= (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
    );

  -- Delete expired database rows
  DELETE FROM public.files
  WHERE expires_at <= (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT;
END;
$$;
