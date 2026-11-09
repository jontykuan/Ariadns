"""Module 8: Rule-Based Next-Step Investigation Recommender."""

import re
from typing import Any
from ariadns.models.config import AppConfig
from ariadns.models.entities import NextStepRecommendation, PropositionNode
from ariadns.storage.db import DatabaseManager

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

class NextStepRecommender:
    def __init__(self, db: DatabaseManager, config: AppConfig):
        self.db = db
        self.config = config

    def recommend(self, session_id: str) -> list[NextStepRecommendation]:
        session_id = session_id.strip().lower()
        propositions = self.db.get_normalized_propositions(session_id, rendered_only=False)
        logs = self.db.get_audit_logs(session_id)
        executed = {(l.module_name.lower(), l.target.lower()) for l in logs}

        recommendations: list[NextStepRecommendation] = []
        rec_counter = 1

        # Find L1 target domain from propositions or session
        l1_domain = session_id
        for p in propositions:
            if p.entity_type == "DOMAIN_L1" and p.target_entity:
                l1_domain = p.target_entity.lower()
                break

        # Rule 1 & 2: CDN Target Investigation
        for p in propositions:
            if p.prop_id == "F1" and "CDN:True" in p.statement:
                # Recommend M2 if not executed
                if ("m2", l1_domain) not in executed:
                    recommendations.append(NextStepRecommendation(
                        rec_id=f"REC_{rec_counter}",
                        trigger_fact_ids=["F1"],
                        recommended_module="m2",
                        recommended_target=l1_domain,
                        rationale="Target is behind CDN proxy; enumerate subdomains to uncover unproxied backend origin IPs.",
                        expected_evidence="Exposed origin subdomains, staging portals, direct A records.",
                        cli_command=f"ariadns step -d {l1_domain} -m m2"
                    ))
                    rec_counter += 1

                # Recommend M3 if not executed
                if ("m3", l1_domain) not in executed:
                    recommendations.append(NextStepRecommendation(
                        rec_id=f"REC_{rec_counter}",
                        trigger_fact_ids=["F1"],
                        recommended_module="m3",
                        recommended_target=l1_domain,
                        rationale="Target is behind CDN proxy; run passive DNS history and host header collision to detect origin IP.",
                        expected_evidence="Historical A records and host header response fingerprint matches.",
                        cli_command=f"ariadns step -d {l1_domain} -m m3"
                    ))
                    rec_counter += 1

        # Rule 3: Unproxied IP Probing
        for p in propositions:
            if p.entity_type in ("SUBDOMAIN", "IP") or "resolves to" in p.statement:
                ips = IP_REGEX.findall(p.statement)
                for ip in ips:
                    if ip not in ("127.0.0.1", "0.0.0.0") and not ip.startswith("104.21.") and not ip.startswith("172.67."):
                        # Non-CDN IP candidate
                        if ("m1", ip) not in executed:
                            recommendations.append(NextStepRecommendation(
                                rec_id=f"REC_{rec_counter}",
                                trigger_fact_ids=[p.prop_id],
                                recommended_module="m1",
                                recommended_target=ip,
                                rationale=f"Unproxied candidate origin host IP {ip} exposed; probe open ports, banner, and cloud provider.",
                                expected_evidence="Origin web server banner, open SSH/admin ports, cloud subscriber details.",
                                cli_command=f"ariadns step -d {session_id} -m m1 --target {ip}"
                            ))
                            rec_counter += 1

                        if ("m4", ip) not in executed:
                            recommendations.append(NextStepRecommendation(
                                rec_id=f"REC_{rec_counter}",
                                trigger_fact_ids=[p.prop_id],
                                recommended_module="m4",
                                recommended_target=ip,
                                rationale=f"Unproxied candidate origin host IP {ip} exposed; run reverse IP pivoting to discover co-hosted domains.",
                                expected_evidence="Same-origin co-hosted sibling domains and infrastructure associations.",
                                cli_command=f"ariadns step -d {session_id} -m m4 --target {ip} --type reverse_ip"
                            ))
                            rec_counter += 1

        # Rule 4: High Confidence L2 Expansion
        for p in propositions:
            if p.node_kind == "CONCLUSION" and "Confidence: HIGH" in p.statement and p.entity_type == "DOMAIN_L2":
                l2_domain = p.target_entity.lower()
                if ("m1", l2_domain) not in executed:
                    recommendations.append(NextStepRecommendation(
                        rec_id=f"REC_{rec_counter}",
                        trigger_fact_ids=p.premises,
                        recommended_module="m1",
                        recommended_target=l2_domain,
                        rationale=f"High-confidence correlated domain {l2_domain} identified; probe DNS and registrar identity.",
                        expected_evidence="Registrant KYC, nameserver host, and operator identity links.",
                        cli_command=f"ariadns step -d {session_id} -m m1 --target {l2_domain}"
                    ))
                    rec_counter += 1

        return recommendations
