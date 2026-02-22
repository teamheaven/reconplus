import subprocess

def get_docker_port_bindings():
    """
    Returns a dict of container ports:
    {
        6379: {
            "container": "redis",
            "image": "redis:7",
            "host_ip": "",
            "host_port": None,
            "network_mode": "bridge"
        }
    }
    """
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}"],
        capture_output=True,
        text=True
    )

    ports = {}

    for line in result.stdout.splitlines():
        name, image, port_info = line.split("|")

        if not port_info:
            continue

        # Example formats:
        # "6379/tcp"
        # "0.0.0.0:6379->6379/tcp"
        entries = port_info.split(",")

        for entry in entries:
            entry = entry.strip()

            if "->" in entry:
                # Published port
                host, container = entry.split("->")
                if ":" in host:
                    host_ip, host_port = host.rsplit(":", 1)
                else:
                    host_ip = ""
                    host_port = host

                container_port = int(container.split("/")[0])
                ports[container_port] = {
                    "container": name,
                    "image": image,
                    "host_ip": host_ip,
                    "host_port": int(host_port),
                    "network_mode": "bridge"
                }
            else:
                # Container-only port
                container_port = int(entry.split("/")[0])
                ports[container_port] = {
                    "container": name,
                    "image": image,
                    "host_ip": "",
                    "host_port": None,
                    "network_mode": "bridge"
                }

    return ports
