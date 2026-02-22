import json
from pathlib import Path


def generate_html_report(recon_data, output_path="output/report.html"):
    Path("output").mkdir(exist_ok=True)

    services_rows = ""
    for svc in recon_data.get("services", []):
        services_rows += f"""
        <tr>
            <td>{svc.get('service')}</td>
            <td>{svc.get('port')}</td>
            <td>{svc.get('base_risk')}</td>
            <td>{svc.get('numeric_score')}</td>
            <td>{svc.get('exposure', {}).get('level')}</td>
        </tr>
        """

    privesc_rows = ""
    for f in recon_data.get("privesc_findings", []):
        privesc_rows += f"""
        <tr>
            <td>{f.get('type')}</td>
            <td>{f.get('risk')}</td>
            <td>{f.get('reason')}</td>
        </tr>
        """
    
    recommendation_rows = ""
    for r in recon_data.get("recommendations", []):
        recommendation_rows += f"""
        <tr>
            <td>{r.get('priority')}</td>
            <td>{r.get('issue')}</td>
            <td>{r.get('action')}</td>
        </tr>
        """

    chains_section = ""
    for chain in recon_data.get("attack_chains", []):
        steps = "<br>".join(chain.get("attack_steps", []))
        mitre = "<br>".join(
            f"{m['id']} - {m['technique']}" for m in chain.get("mitre_attack", [])
        )

        chains_section += f"""
        <div class="chain">
            <h4>{chain.get('entry_service')} (Port {chain.get('port')})</h4>
            <p><strong>Impact:</strong> {chain.get('final_impact')}</p>
            <p><strong>Steps:</strong><br>{steps}</p>
            <p><strong>MITRE Mapping:</strong><br>{mitre}</p>
        </div>
        """

    html_content = f"""
    <html>
    <head>
        <title>ReconGuard Security Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; background: #f4f6f8; }}
            h1, h2 {{ color: #1a1a1a; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            .score-box {{
                padding: 20px;
                background: #ffffff;
                border-left: 6px solid #e74c3c;
                margin-bottom: 30px;
                font-size: 18px;
            }}
            .chain {{
                background: white;
                padding: 15px;
                margin-bottom: 15px;
                border-left: 4px solid #2980b9;
            }}
        </style>
    </head>
    <body>

        <h1>ReconGuard Executive Security Report</h1>

        <div class="score-box">
            <strong>Overall Numeric Risk Score:</strong> {recon_data.get('overall_numeric_score')} / 10<br>
            <strong>Compromise Probability:</strong> {recon_data.get('compromise_probability_percent')}%
        </div>

        <h2>Services</h2>
        <table>
            <tr>
                <th>Service</th>
                <th>Port</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Exposure</th>
            </tr>
            {services_rows}
        </table>

        <h2>Privilege Escalation Findings</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Risk</th>
                <th>Reason</th>
            </tr>
            {privesc_rows}
        </table>

        <h2>Attack Chains</h2>
        {chains_section}

        <div class="card">
        <h2>Recommended Actions</h2>
        <table>
        <tr>
            <th>Priority</th>
            <th>Issue</th>
            <th>Recommended Action</th>
        </tr>
            {recommendation_rows}
        </table>
        </div>
    </body>
    </html>
    """

    with open(output_path, "w") as f:
        f.write(html_content)

    return output_path