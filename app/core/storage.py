import sqlite3
from pathlib import Path


class Storage:

    def __init__(self, db_path="data/vajra.db"):

        self.db_path = Path(db_path)

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self._create_tables()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _create_tables(self):

        with self._connect() as connection:

            # =========================
            # SCANS TABLE
            # =========================

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    target TEXT,
                    risk_score INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'LOW',
                    threat TEXT DEFAULT 'LOW RISK',
                    action TEXT DEFAULT 'ALLOW',
                    ai_model TEXT,
                    ai_runtime TEXT,
                    ai_status TEXT,
                    ai_backend TEXT,
                    ai_backend_status TEXT,
                    sha256 TEXT
                )
                """
            )

            # =========================
            # INCIDENTS TABLE
            # =========================

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    target TEXT,
                    risk_score INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'LOW',
                    threat TEXT DEFAULT 'LOW RISK',
                    action TEXT DEFAULT 'ALLOW',
                    status TEXT DEFAULT 'OPEN',
                    description TEXT,
                    evidence TEXT
                )
                """
            )

            connection.commit()

            # =========================
            # SCAN MIGRATION
            # =========================

            existing_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(scans)"
                ).fetchall()
            }

            new_columns = {
                "ai_runtime": "TEXT",
                "ai_backend": "TEXT",
                "ai_backend_status": "TEXT",
                "sha256": "TEXT"
            }

            for column, column_type in new_columns.items():

                if column not in existing_columns:

                    connection.execute(
                        f"ALTER TABLE scans ADD COLUMN {column} {column_type}"
                    )

            connection.commit()

    # =========================================
    # SCAN STORAGE
    # =========================================

    def save_scan(self, scan):

        with self._connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO scans (
                    id,
                    timestamp,
                    type,
                    target,
                    risk_score,
                    risk_level,
                    threat,
                    action,
                    ai_model,
                    ai_runtime,
                    ai_status,
                    ai_backend,
                    ai_backend_status,
                    sha256
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.get("id"),
                    scan.get("timestamp"),
                    scan.get("type"),
                    scan.get("target"),
                    int(scan.get("risk_score", 0)),
                    scan.get("risk_level", "LOW"),
                    scan.get("threat", "LOW RISK"),
                    scan.get("action", "ALLOW"),
                    scan.get("ai_model"),
                    scan.get("ai_runtime"),
                    scan.get("ai_status"),
                    scan.get("ai_backend"),
                    scan.get("ai_backend_status"),
                    scan.get("sha256")
                )
            )

            connection.commit()

    def get_scans(self, limit=50):

        limit = max(
            1,
            min(int(limit), 50)
        )

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    type,
                    target,
                    risk_score,
                    risk_level,
                    threat,
                    action,
                    ai_model,
                    ai_runtime,
                    ai_status,
                    ai_backend,
                    ai_backend_status,
                    sha256
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def get_scan_count(self):

        with self._connect() as connection:

            row = connection.execute(
                "SELECT COUNT(*) FROM scans"
            ).fetchone()

        return int(row[0])

    def clear_scans(self):

        with self._connect() as connection:

            connection.execute(
                "DELETE FROM scans"
            )

            connection.commit()

    def get_next_scan_id(self):

        with self._connect() as connection:

            row = connection.execute(
                "SELECT MAX(id) FROM scans"
            ).fetchone()

        maximum_id = row[0]

        if maximum_id is None:
            return 1

        return int(maximum_id) + 1

    # =========================================
    # INCIDENT STORAGE
    # =========================================

    def save_incident(self, incident):

        with self._connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    id,
                    timestamp,
                    type,
                    target,
                    risk_score,
                    risk_level,
                    threat,
                    action,
                    status,
                    description,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.get("id"),
                    incident.get("timestamp"),
                    incident.get("type"),
                    incident.get("target"),
                    int(incident.get("risk_score", 0)),
                    incident.get("risk_level", "LOW"),
                    incident.get("threat", "LOW RISK"),
                    incident.get("action", "ALLOW"),
                    incident.get("status", "OPEN"),
                    incident.get("description", ""),
                    str(incident.get("evidence", []))
                )
            )

            connection.commit()

    def get_incidents(self, limit=100):

        limit = max(
            1,
            min(int(limit), 100)
        )

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    type,
                    target,
                    risk_score,
                    risk_level,
                    threat,
                    action,
                    status,
                    description,
                    evidence
                FROM incidents
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        incidents = []

        for row in rows:

            incident = dict(row)

            incidents.append(incident)

        return incidents

    def get_incident(self, incident_id):

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    type,
                    target,
                    risk_score,
                    risk_level,
                    threat,
                    action,
                    status,
                    description,
                    evidence
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,)
            ).fetchone()

        if row is None:
            return None

        return dict(row)

    def update_incident_status(
        self,
        incident_id,
        status
    ):

        with self._connect() as connection:

            cursor = connection.execute(
                """
                UPDATE incidents
                SET status = ?
                WHERE id = ?
                """,
                (
                    status,
                    incident_id
                )
            )

            connection.commit()

        return cursor.rowcount > 0

    def clear_incidents(self):

        with self._connect() as connection:

            connection.execute(
                "DELETE FROM incidents"
            )

            connection.commit()

    def get_next_incident_id(self):

        with self._connect() as connection:

            row = connection.execute(
                "SELECT MAX(id) FROM incidents"
            ).fetchone()

        maximum_id = row[0]

        if maximum_id is None:
            return 1

        return int(maximum_id) + 1