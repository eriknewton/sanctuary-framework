#!/usr/bin/env python3
"""
Ping Identity Agent Gateway Integration Example

This example demonstrates the full authorization flow:
1. Generate a Sovereignty Health Report (SHR) via Sanctuary MCP
2. Transform it for Ping Identity's Agent Gateway
3. Simulate authorization decisions based on sovereignty posture
4. Show how different sovereignty profiles map to constraints

Run this with a Sanctuary MCP server running locally on stdio.
"""

import json
import sys
from typing import Optional, Any
from datetime import datetime, timedelta


def create_mock_shr(
    instance_id: str = "agent-001",
    l1_status: str = "active",
    l2_status: str = "active",
    l3_status: str = "active",
    l4_status: str = "active",
    degradations: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """
    Create a mock SHR for demonstration.
    In real usage, this would come from sanctuary/shr_generate.
    """
    now = datetime.utcnow()
    expires = now + timedelta(hours=1)

    if degradations is None:
        degradations = []

    return {
        "body": {
            "shr_version": "1.0",
            "instance_id": instance_id,
            "generated_at": now.isoformat() + "Z",
            "expires_at": expires.isoformat() + "Z",
            "layers": {
                "l1": {
                    "status": l1_status,
                    "encryption": "aes-256-gcm",
                    "key_custody": "self",
                    "integrity": "hmac-sha256",
                    "identity_type": "ed25519",
                    "state_portable": True,
                },
                "l2": {
                    "status": l2_status,
                    "isolation_type": "local-process" if l2_status == "degraded" else "tee",
                    "attestation_available": l2_status == "active",
                },
                "l3": {
                    "status": l3_status,
                    "proof_system": "schnorr+range-proofs" if l3_status == "active" else "commitment-only",
                    "selective_disclosure": l3_status == "active",
                },
                "l4": {
                    "status": l4_status,
                    "reputation_mode": "sybil-resistant" if l4_status == "active" else "basic",
                    "attestation_format": "ed25519-signed-json",
                    "reputation_portable": True,
                },
            },
            "capabilities": {
                "handshake": True,
                "shr_exchange": True,
                "reputation_verify": True,
                "encrypted_channel": l1_status == "active",
            },
            "degradations": degradations,
        },
        "signed_by": "FQyK2z-zxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",  # mock public key
        "signature": "signature_placeholder_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    }


def simulate_authorization_decision(context: dict[str, Any]) -> dict[str, Any]:
    """
    Simulate Ping Identity Agent Gateway authorization decision.

    Real implementation would:
    1. Verify the SHR signature
    2. Check SHR expiry
    3. Evaluate against configured policies
    4. Apply additional identity context (e.g., MFA status)
    5. Return authorization decision + constraints
    """
    score = context["overall_score"]
    constraints = context["recommended_constraints"]

    decision = {
        "decision": "approve" if score >= 40 else "deny",
        "trust_level": context["recommended_trust_level"],
        "applied_constraints": [c["type"] for c in constraints if c["priority"] == "high"],
        "reasoning": [],
    }

    if score >= 80:
        decision["reasoning"].append("High sovereignty score: allow autonomous operation")
    elif score >= 60:
        decision["reasoning"].append("Good sovereignty: elevated trust with write constraints")
    elif score >= 40:
        decision["reasoning"].append("Moderate sovereignty: standard access with approval gates")
    else:
        decision["reasoning"].append("Low sovereignty: deny or restrict to identity verification")

    return decision


def print_authorization_context(context: dict[str, Any]) -> None:
    """Pretty-print an authorization context."""
    print("\n" + "=" * 80)
    print("PING IDENTITY AUTHORIZATION CONTEXT")
    print("=" * 80)

    print(f"\nAgent Identity: {context['agent_identity'][:16]}...")
    print(f"Generated: {context['generated_at']}")
    print(f"Expires: {context['context_expires_at']}")

    print("\n--- SOVEREIGNTY SCORES ---")
    print(f"Overall Score:        {context['overall_score']}/100")
    print(f"L1 (Cognitive):       {context['layer_scores']['l1_cognitive']}/100")
    print(f"L2 (Operational):     {context['layer_scores']['l2_operational']}/100")
    print(f"L3 (Disclosure):      {context['layer_scores']['l3_disclosure']}/100")
    print(f"L4 (Reputation):      {context['layer_scores']['l4_reputation']}/100")

    print("\n--- RECOMMENDED TRUST LEVEL ---")
    print(f"Trust Level: {context['recommended_trust_level'].upper()}")

    print("\n--- LAYER STATUS ---")
    for layer, status in context["layer_status"].items():
        print(f"{layer.upper()}: {status}")

    print("\n--- AUTHORIZATION SIGNALS ---")
    signals = context["authorization_signals"]
    signal_names = {
        "approval_gate_active": "Approval Gate",
        "context_gating_active": "Context Gating",
        "encryption_at_rest": "Encryption at Rest",
        "behavioral_baseline_active": "Anomaly Detection",
        "identity_verified": "Cryptographic Identity",
        "zero_knowledge_capable": "Zero-Knowledge Proofs",
        "selective_disclosure_active": "Selective Disclosure",
        "reputation_portable": "Portable Reputation",
        "handshake_capable": "Sovereignty Handshake",
    }

    for key, name in signal_names.items():
        status = "✓" if signals[key] else "✗"
        print(f"  {status} {name}")

    if context["degradations"]:
        print("\n--- DEGRADATIONS ---")
        for deg in context["degradations"]:
            print(f"  [{deg['severity'].upper()}] {deg['code']}")
            print(f"    Impact: {deg['authorization_impact']}")

    if context["recommended_constraints"]:
        print("\n--- RECOMMENDED CONSTRAINTS ---")
        for constraint in context["recommended_constraints"]:
            priority_marker = (
                "!" if constraint["priority"] == "high"
                else "*" if constraint["priority"] == "medium"
                else "-"
            )
            print(f"  [{priority_marker}] {constraint['type'].upper()}")
            print(f"      {constraint['description']}")
            print(f"      Reason: {constraint['rationale']}")


def print_authorization_decision(decision: dict[str, Any]) -> None:
    """Pretty-print an authorization decision."""
    print("\n" + "-" * 80)
    print("AUTHORIZATION DECISION")
    print("-" * 80)

    decision_text = decision["decision"].upper()
    decision_color = "✓ APPROVE" if decision["decision"] == "approve" else "✗ DENY"

    print(f"\nDecision: {decision_color}")
    print(f"Trust Level: {decision['trust_level']}")

    if decision["applied_constraints"]:
        print("\nApplied Constraints:")
        for constraint in decision["applied_constraints"]:
            print(f"  • {constraint}")

    print("\nReasoning:")
    for reason in decision["reasoning"]:
        print(f"  • {reason}")


def demonstrate_full_sovereign_agent() -> None:
    """Demonstrate an agent with full sovereignty."""
    print("\n\n" + "#" * 80)
    print("SCENARIO 1: FULLY SOVEREIGN AGENT")
    print("#" * 80)

    shr = create_mock_shr(instance_id="agent-full-sovereignty")

    # Mock transformation (would come from gateway-adapter.ts)
    context = {
        "shr_version": "1.0",
        "agent_identity": shr["signed_by"],
        "generated_at": shr["body"]["generated_at"],
        "context_expires_at": shr["body"]["expires_at"],
        "overall_score": 95,
        "recommended_trust_level": "full",
        "layer_scores": {
            "l1_cognitive": 100,
            "l2_operational": 95,
            "l3_disclosure": 100,
            "l4_reputation": 100,
        },
        "layer_status": {
            "l1_cognitive": "active",
            "l2_operational": "active",
            "l3_disclosure": "active",
            "l4_reputation": "active",
        },
        "authorization_signals": {
            "approval_gate_active": True,
            "context_gating_active": True,
            "encryption_at_rest": True,
            "behavioral_baseline_active": True,
            "identity_verified": True,
            "zero_knowledge_capable": True,
            "selective_disclosure_active": True,
            "reputation_portable": True,
            "handshake_capable": True,
        },
        "degradations": [],
        "recommended_constraints": [],
        "shr_signature": shr["signature"],
        "shr_signed_by": shr["signed_by"],
    }

    print_authorization_context(context)

    decision = simulate_authorization_decision(context)
    print_authorization_decision(decision)


def demonstrate_degraded_l2_agent() -> None:
    """Demonstrate an agent with L2 (operational) degradation."""
    print("\n\n" + "#" * 80)
    print("SCENARIO 2: DEGRADED L2 AGENT (No TEE, Process Isolation Only)")
    print("#" * 80)

    degradations = [
        {
            "layer": "l2",
            "code": "PROCESS_ISOLATION_ONLY",
            "severity": "warning",
            "description": "Process-level isolation only (no TEE)",
        },
        {
            "layer": "l2",
            "code": "SELF_REPORTED_ATTESTATION",
            "severity": "warning",
            "description": "Attestation is self-reported (no hardware root of trust)",
        },
    ]

    shr = create_mock_shr(
        instance_id="agent-degraded-l2",
        l2_status="degraded",
        degradations=degradations,
    )

    context = {
        "shr_version": "1.0",
        "agent_identity": shr["signed_by"],
        "generated_at": shr["body"]["generated_at"],
        "context_expires_at": shr["body"]["expires_at"],
        "overall_score": 65,
        "recommended_trust_level": "elevated",
        "layer_scores": {
            "l1_cognitive": 100,
            "l2_operational": 50,
            "l3_disclosure": 100,
            "l4_reputation": 100,
        },
        "layer_status": {
            "l1_cognitive": "active",
            "l2_operational": "degraded",
            "l3_disclosure": "active",
            "l4_reputation": "active",
        },
        "authorization_signals": {
            "approval_gate_active": True,
            "context_gating_active": True,
            "encryption_at_rest": True,
            "behavioral_baseline_active": False,
            "identity_verified": True,
            "zero_knowledge_capable": True,
            "selective_disclosure_active": True,
            "reputation_portable": True,
            "handshake_capable": True,
        },
        "degradations": [
            {
                "layer": "l2",
                "code": "PROCESS_ISOLATION_ONLY",
                "severity": "warning",
                "authorization_impact": "Restricted to read-only operations until TEE available",
            },
        ],
        "recommended_constraints": [
            {
                "type": "read_only",
                "description": "Restrict to read-only operations until operational isolation improves",
                "rationale": "L2 isolation is process-level only (no TEE)",
                "priority": "high",
            },
            {
                "type": "requires_approval",
                "description": "Human approval required for writes",
                "rationale": "No attestation available — self-reported integrity only",
                "priority": "high",
            },
        ],
        "shr_signature": shr["signature"],
        "shr_signed_by": shr["signed_by"],
    }

    print_authorization_context(context)

    decision = simulate_authorization_decision(context)
    print_authorization_decision(decision)


def demonstrate_heavily_degraded_agent() -> None:
    """Demonstrate an agent with multiple layer degradations."""
    print("\n\n" + "#" * 80)
    print("SCENARIO 3: HEAVILY DEGRADED AGENT (Multiple Layer Issues)")
    print("#" * 80)

    degradations = [
        {
            "layer": "l2",
            "code": "PROCESS_ISOLATION_ONLY",
            "severity": "warning",
            "description": "Process-level isolation only (no TEE)",
        },
        {
            "layer": "l3",
            "code": "COMMITMENT_ONLY",
            "severity": "info",
            "description": "Commitment schemes only (no ZK proofs)",
        },
    ]

    shr = create_mock_shr(
        instance_id="agent-heavily-degraded",
        l2_status="degraded",
        l3_status="degraded",
        degradations=degradations,
    )

    context = {
        "shr_version": "1.0",
        "agent_identity": shr["signed_by"],
        "generated_at": shr["body"]["generated_at"],
        "context_expires_at": shr["body"]["expires_at"],
        "overall_score": 45,
        "recommended_trust_level": "standard",
        "layer_scores": {
            "l1_cognitive": 100,
            "l2_operational": 50,
            "l3_disclosure": 60,
            "l4_reputation": 100,
        },
        "layer_status": {
            "l1_cognitive": "active",
            "l2_operational": "degraded",
            "l3_disclosure": "degraded",
            "l4_reputation": "active",
        },
        "authorization_signals": {
            "approval_gate_active": True,
            "context_gating_active": False,
            "encryption_at_rest": True,
            "behavioral_baseline_active": False,
            "identity_verified": True,
            "zero_knowledge_capable": False,
            "selective_disclosure_active": False,
            "reputation_portable": True,
            "handshake_capable": True,
        },
        "degradations": [
            {
                "layer": "l2",
                "code": "PROCESS_ISOLATION_ONLY",
                "severity": "warning",
                "authorization_impact": "Restricted to read-only operations until TEE available",
            },
            {
                "layer": "l3",
                "code": "COMMITMENT_ONLY",
                "severity": "info",
                "authorization_impact": "Limited data sharing scope — no zero-knowledge proofs",
            },
        ],
        "recommended_constraints": [
            {
                "type": "read_only",
                "description": "Restrict to read-only operations",
                "rationale": "L2 isolation is process-level only",
                "priority": "high",
            },
            {
                "type": "restricted_scope",
                "description": "Limit data sharing scope — no selective disclosure",
                "rationale": "Agent cannot redact data or prove predicates without revealing all context",
                "priority": "high",
            },
            {
                "type": "requires_approval",
                "description": "Human approval for sensitive operations",
                "rationale": "Multiple sovereignty gaps",
                "priority": "medium",
            },
        ],
        "shr_signature": shr["signature"],
        "shr_signed_by": shr["signed_by"],
    }

    print_authorization_context(context)

    decision = simulate_authorization_decision(context)
    print_authorization_decision(decision)


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("SANCTUARY + PING IDENTITY GATEWAY INTEGRATION EXAMPLE")
    print("=" * 80)
    print("\nThis demonstrates how Sovereignty Health Reports (SHRs) translate to")
    print("authorization decisions in Ping Identity's Agent Gateway.\n")

    demonstrate_full_sovereign_agent()
    demonstrate_degraded_l2_agent()
    demonstrate_heavily_degraded_agent()

    print("\n\n" + "=" * 80)
    print("KEY TAKEAWAYS")
    print("=" * 80)
    print("""
1. SOVEREIGNTY SCORE DRIVES TRUST LEVEL
   - Score ≥ 80: "full" trust → autonomous operation
   - Score 60-79: "elevated" trust → read-only or approval gates
   - Score 40-59: "standard" trust → human approval required
   - Score < 40: "restricted" trust → identity verification required

2. DEGRADATIONS MAP TO CONSTRAINTS
   - L2 degradation (no TEE) → read_only constraint
   - L3 degradation (no ZK) → restricted_scope constraint
   - Multiple degradations → identity_verification_required

3. CONSTRAINTS ARE RECOMMENDATIONS
   - The Ping Gateway makes the final authorization decision
   - Constraints can be refined with additional context
   - Organizations can layer their own policies on top

4. SIGNATURE VERIFICATION IS CRITICAL
   - Always verify SHR signature before trusting scores
   - Check SHR expiry before accepting context
   - Store verified SHRs in an audit log
""")
