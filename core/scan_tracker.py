from datetime import datetime
import uuid

def generate_scan_metadata():
    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "scanner_version": "ReconGuard v0.1"
    }
