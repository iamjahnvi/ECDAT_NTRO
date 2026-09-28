"""seed_ntro_db.py — explicit NTRO prototype database initialization.

Usage (from backend/):
    python seed_ntro_db.py            # create + seed if needed (idempotent)
    python seed_ntro_db.py --reset    # delete the database file and reseed

Known demo credentials are supplied via the environment, never in this file:
    NTRO_SEED_PASSWORD_001 / NTRO_SEED_PASSWORD_002
See backend/NTRO_GITHUB_SETUP.md for the documented demo values.

This script NEVER prints passwords, hashes, tokens, or encryption keys.
"""
import argparse
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ntro_database


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize the NTRO prototype database.")
    parser.add_argument("--reset", action="store_true",
                        help="Delete the existing database file and reseed from scratch.")
    args = parser.parse_args()

    path = ntro_database.db_path()
    if args.reset and path.exists():
        path.unlink()
        print(f"Removed existing database: {path}")

    ntro_database.init_db()

    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        employees = conn.execute(
            "SELECT employee_id, name, department, active FROM ntro_employees ORDER BY employee_id"
        ).fetchall()
        auths = conn.execute(
            "SELECT employee_id, connected_at FROM github_authorizations ORDER BY employee_id"
        ).fetchall()

    print(f"Database: {path}")
    print(f"Tables: {', '.join(tables)}")
    print("Employees:")
    for row in employees:
        print(f"  - {row['employee_id']} | {row['name']} | {row['department']} "
              f"| active={bool(row['active'])}")
    print(f"GitHub authorizations: {len(auths)}")
    for row in auths:
        print(f"  - {row['employee_id']} (connected {row['connected_at']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
