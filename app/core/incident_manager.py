from datetime import datetime
from app.core.storage import Storage


class IncidentManager:

    def __init__(self):

        self.storage = Storage()

        self.incidents = self.storage.get_incidents(
            limit=100
        )

        self.incident_id = (
            self.storage.get_next_incident_id() - 1
        )

    def create_incident(
        self,
        incident_type,
        target,
        risk_score=0,
        risk_level="LOW",
        threat="LOW RISK",
        action="ALLOW",
        evidence=None,
        description=""
    ):

        self.incident_id += 1

        incident = {

            "id": self.incident_id,

            "timestamp":
                datetime.now().isoformat(),

            "type":
                incident_type,

            "target":
                target,

            "risk_score":
                int(risk_score),

            "risk_level":
                str(risk_level).upper(),

            "threat":
                threat,

            "action":
                action,

            "status":
                "OPEN",

            "description":
                description,

            "evidence":
                evidence or []
        }

        # Save to SQLite
        self.storage.save_incident(
            incident
        )

        # Keep memory cache
        self.incidents.insert(
            0,
            incident
        )

        self.incidents = (
            self.incidents[:100]
        )

        return incident

    def get_incidents(self, limit=20):

        limit = max(
            1,
            min(int(limit), 100)
        )

        self.incidents = (
            self.storage.get_incidents(
                limit=100
            )
        )

        return self.incidents[:limit]

    def get_incident(self, incident_id):

        incident = (
            self.storage.get_incident(
                incident_id
            )
        )

        return incident

    def update_status(
        self,
        incident_id,
        status
    ):

        status = str(status).upper()

        updated = (
            self.storage.update_incident_status(
                incident_id,
                status
            )
        )

        if not updated:
            return None

        for incident in self.incidents:

            if incident["id"] == incident_id:

                incident["status"] = status

                break

        return self.storage.get_incident(
            incident_id
        )

    def clear_incidents(self):

        self.storage.clear_incidents()

        self.incidents.clear()

        self.incident_id = 0