import subprocess

def get_network_info():
    result = subprocess.run(
        ["ip", "-o", "-4", "addr", "show"],
        capture_output=True,
        text=True
    )

    interfaces = []
    for line in result.stdout.splitlines():
        parts = line.split()
        interfaces.append({
            "interface": parts[1],
            "ip_address": parts[3]
        })

    return {
        "interfaces": interfaces
    }
