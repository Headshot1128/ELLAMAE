ALTER TABLE applications ADD COLUMN min_version TEXT DEFAULT '1.0.0';
ALTER TABLE applications ADD COLUMN download_url TEXT DEFAULT '';
INSERT INTO schema_migrations(version) VALUES(8);
