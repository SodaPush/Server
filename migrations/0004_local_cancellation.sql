ALTER TABLE push_jobs ADD COLUMN local_cancelled_at TEXT;
ALTER TABLE push_jobs ADD COLUMN local_cancellation_job_id TEXT;
