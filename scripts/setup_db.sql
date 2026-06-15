-- Create application user
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'honeypot_user') THEN
      CREATE USER honeypot_user WITH PASSWORD 'MERCHISEDECK';
   END IF;
END
$$;

-- Grant privileges (run after DB is created)
GRANT ALL PRIVILEGES ON DATABASE honeypot_db TO honeypot_user;
GRANT ALL PRIVILEGES ON DATABASE honeypot_db TO postgres;
