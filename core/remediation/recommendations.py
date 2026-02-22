def generate_recommendations(services, privesc_findings):

    recommendations = []
    seen = set()

    for svc in services:
        if svc.get("numeric_score", 0) >= 7:
            issue = f"{svc.get('service')} exposed on port {svc.get('port')}"
            action = "Restrict public exposure using firewall rules or disable if not required."

            key = (issue, action)
            if key not in seen:
                seen.add(key)
                recommendations.append({
                    "priority": "IMMEDIATE",
                    "issue": issue,
                    "action": action
                })

    for finding in privesc_findings:
        if finding.get("type") == "SUDO_FULL_ACCESS":
            key = ("Unrestricted sudo access", "Restrict sudo permissions using least privilege principle.")
            if key not in seen:
                seen.add(key)
                recommendations.append({
                    "priority": "IMMEDIATE",
                    "issue": key[0],
                    "action": key[1]
                })

        if finding.get("type") == "DOCKER_GROUP_ABUSE":
            key = ("User in docker group", "Remove user from docker group or enforce rootless containers.")
            if key not in seen:
                seen.add(key)
                recommendations.append({
                    "priority": "IMMEDIATE",
                    "issue": key[0],
                    "action": key[1]
                })

        if finding.get("type") == "PATH_HIJACK":
            key = ("Writable directory in PATH", "Remove write permissions or reorder PATH to prevent hijacking.")
            if key not in seen:
                seen.add(key)
                recommendations.append({
                    "priority": "HIGH",
                    "issue": key[0],
                    "action": key[1]
                })

    return recommendations