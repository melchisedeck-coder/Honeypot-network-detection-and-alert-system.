#!/bin/bash
# Daily database backup script
PGPASSWORD="MERCHISEDECK"
BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="$BACKUP_DIR/honeypot_db_$TIMESTAMP.sql"

mkdir -p "$BACKUP_DIR"

echo "Backing up honeypot_db to $FILENAME ..."
"C:/Program Files/PostgreSQL/18/bin/pg_dump.exe" \
  -U postgres \
  -d honeypot_db \
  -f "$FILENAME"

echo "Backup complete: $FILENAME"

# Keep only last 30 backups
ls -t "$BACKUP_DIR"/*.sql 2>/dev/null | tail -n +31 | xargs rm -f
echo "Old backups cleaned up."
