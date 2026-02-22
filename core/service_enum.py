import subprocess
from core.service_intel import SERVICE_MAP


def extract_port(address):
    try:
        return int(address.rsplit(":", 1)[-1])
    except Exception:
        return None


def get_running_services():
    result = subprocess.run(
        ["ss", "-tulnp"],
        capture_output=True,
        text=True
    )

    services = []

    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        port = extract_port(parts[4])
        if port is None:
            continue

        intel = SERVICE_MAP.get(
            port,
            {"name": "UNKNOWN", "risk": "UNKNOWN"}
        )

        services.append({
            "protocol": parts[0],
            "port": port,
            "service": intel["name"],
            "risk": intel["risk"],
            "process": parts[-1]
        })

    return services
