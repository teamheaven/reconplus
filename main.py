import json

from core.system_info import get_system_info
from core.network_info import get_network_info
from core.service_enum import get_running_services
from core.scan_tracker import generate_scan_metadata
from core.data_cleaner import deduplicate_services
from core.cve_enricher import enrich_services_with_cves
from core.exposure_classifier import classify_exposure
from core.risk_adjuster import adjust_risk
from core.risk_analyzer import analyze_risk
from core.privesc.privesc_engine import run_privesc_analysis
from core.attack_chain.chain_builder import build_attack_chains
from core.mitre.attack_mapper import enrich_chains_with_mitre
from core.risk.chain_escalator import escalate_service_risk
from core.reporting.html_report import generate_html_report
from core.remediation.recommendations import generate_recommendations
from core.reporting.pdf_report import generate_pdf_report
from core.executive.summary import generate_executive_summary
from core.scoring.cvss_engine import (
    score_services,
    calculate_overall_risk,
    compromise_probability
)


def run_recon():
    # Phase 1: Service Enumeration
    raw_services = get_running_services()
    services = deduplicate_services(raw_services)

    # Phase 2: CVE Enrichment
    services = enrich_services_with_cves(services)

    final_services = []

    # Phase 3: Exposure + Risk Logic
    for svc in services:
        base_risk = svc.get("risk", "UNKNOWN")

        exposure_info = classify_exposure(svc)
        adjusted_risk = adjust_risk(base_risk, exposure_info["level"])

        svc["base_risk"] = base_risk
        svc["exposure"] = exposure_info
        svc["adjusted_risk"] = adjusted_risk

        final_services.append(svc)

    # Phase 4: Privilege Escalation
    privesc_findings = run_privesc_analysis()

    # Phase 5: Attack Chains
    attack_chains = build_attack_chains(final_services, privesc_findings)
    attack_chains = enrich_chains_with_mitre(attack_chains)

    # Phase 6: Escalate risk using chains
    final_services = escalate_service_risk(final_services, attack_chains)

    # Phase 7: Numeric scoring
    final_services = score_services(final_services)
    overall_score = calculate_overall_risk(final_services)
    compromise_prob = compromise_probability(overall_score)

    # Phase 8: Risk Summary
    risk_summary = analyze_risk(final_services)

    # Phase 9: Recommendations
    recommendations = generate_recommendations(final_services, privesc_findings)

    # ✅ Build recon_data FIRST
    recon_data = {
        "metadata": generate_scan_metadata(),
        "system": get_system_info(),
        "network": get_network_info(),
        "risk_summary": risk_summary,
        "overall_numeric_score": overall_score,
        "compromise_probability_percent": compromise_prob,
        "services": final_services,
        "privesc_findings": privesc_findings,
        "attack_chains": attack_chains,
        "recommendations": recommendations
    }

    # ✅ NOW generate executive summary
    executive_summary = generate_executive_summary(recon_data)
    recon_data["executive_summary"] = executive_summary

    # Save JSON output
    with open("output/recon.json", "w") as f:
        json.dump(recon_data, f, indent=4)

    # Generate HTML report
    report_path = generate_html_report(recon_data)
    print(f"\nHTML report generated at: {report_path}")

    # Generate PDF report
    pdf_path = generate_pdf_report(recon_data)
    print(f"PDF report generated at: {pdf_path}")

    print("[+] Recon completed successfully")
    print("[+] Scan ID:", recon_data["metadata"]["scan_id"])
    print("[+] Risk Summary:", risk_summary)
    print("[+] Privilege Escalation Findings:", len(privesc_findings))


if __name__ == "__main__":
    run_recon()