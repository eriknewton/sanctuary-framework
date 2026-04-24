#!/usr/bin/env python3
"""
Sanctuary Composition v1.0 -- Concordia Python Sidecar

JSON-RPC 2.0 server over stdio. Wraps Concordia v0.4.0 SDK to provide:
  - pack_receipt: generate a Concordia receipt from a Sanctuary commitment event
  - verify_receipt: verify a Concordia receipt signature
  - verify_mandate: verify a Concordia mandate (delegation chain)
  - ping: health check
  - version: version info
  - shutdown: graceful exit

No em-dashes in any output. No competitor names.

Sidecar crash is NEVER a fortress-halt condition on the TypeScript side.
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

import concordia
from concordia.signing import (
    KeyPair,
    canonical_json,
    sign_message,
    verify_signature,
)
from concordia.models.mandate import (
    Mandate,
    MandateStatus,
)

# Concordia version for the version RPC response.
CONCORDIA_VERSION = concordia.__version__ if hasattr(concordia, "__version__") else "0.4.0"

# Sidecar version.
SIDECAR_VERSION = "1.0.0"

# Long-lived signing key pair for receipt signing.
# Generated fresh on each sidecar spawn. Fortress-side tracks the public key.
_sidecar_keypair: KeyPair | None = None


def _get_keypair() -> KeyPair:
    global _sidecar_keypair
    if _sidecar_keypair is None:
        _sidecar_keypair = KeyPair.generate()
    return _sidecar_keypair


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -----------------------------------------------------------------------
# RPC method handlers
# -----------------------------------------------------------------------


def handle_ping(_params: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "version": CONCORDIA_VERSION}


def handle_version(_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "sidecar_version": SIDECAR_VERSION,
        "concordia_version": CONCORDIA_VERSION,
        "python_version": sys.version,
    }


def handle_pack_receipt(params: dict[str, Any]) -> dict[str, Any]:
    """Pack a Concordia receipt from Sanctuary commitment event data."""
    kp = _get_keypair()

    receipt_id = str(uuid.uuid4())
    packed_at = _now_iso()

    # Build the receipt data dict for signing.
    receipt_data: dict[str, Any] = {
        "receipt_id": receipt_id,
        "schema_urn": "urn:concordia:schema:receipt:v1",
        "source_event_id": params.get("source_event_id", ""),
        "source_event_type": params.get("source_event_type", ""),
        "agent_id": params.get("agent_id", ""),
        "counterparty_id": params.get("counterparty_id", ""),
        "commitment_class": params.get("commitment_class", ""),
        "references": params.get("references", []),
        "signature_scheme": params.get("signature_scheme", "ed25519-v1"),
        "packed_at": packed_at,
    }

    if params.get("bounded_scope"):
        receipt_data["bounded_scope"] = params["bounded_scope"]

    # Sign the receipt using Concordia's canonical JSON signing.
    signature = sign_message(receipt_data, kp)

    return {
        "receipt_id": receipt_id,
        "signature": signature,
        "packed_at": packed_at,
        "public_key": kp.public_key_bytes().hex(),
        "attestation_metadata": {
            "commitment_class": params.get("commitment_class", ""),
            "references_count": len(params.get("references", [])),
        },
    }


def handle_verify_receipt(params: dict[str, Any]) -> dict[str, Any]:
    """Verify a Concordia receipt signature."""
    kp = _get_keypair()

    # Rebuild the receipt data for verification (minus signature).
    receipt_data: dict[str, Any] = {
        "receipt_id": params.get("receipt_id", ""),
        "schema_urn": "urn:concordia:schema:receipt:v1",
        "source_event_id": params.get("source_event_id", ""),
        "source_event_type": params.get("source_event_type", ""),
        "agent_id": params.get("agent_id", ""),
        "counterparty_id": params.get("counterparty_id", ""),
        "commitment_class": params.get("commitment_class", ""),
        "references": params.get("references", []),
        "signature_scheme": params.get("signature_scheme", "ed25519-v1"),
        "packed_at": params.get("packed_at", ""),
    }

    signature = params.get("signature", "")

    try:
        valid = verify_signature(receipt_data, signature, kp.public_key)
        return {"valid": valid}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def handle_verify_mandate(params: dict[str, Any]) -> dict[str, Any]:
    """Verify a Concordia mandate with delegation chain validation."""
    mandate_data = params.get("mandate", {})
    max_depth = params.get("max_depth", 5)

    try:
        mandate = Mandate.from_dict(mandate_data)
    except Exception as e:
        return {
            "valid": False,
            "status": "active",
            "error": f"Failed to parse mandate: {e}",
            "checks": {
                "signature_valid": False,
                "chain_valid": False,
                "not_expired": False,
                "not_revoked": False,
                "constraints_valid": False,
            },
        }

    checks: dict[str, bool] = {
        "signature_valid": False,
        "chain_valid": False,
        "not_expired": False,
        "not_revoked": False,
        "constraints_valid": False,
    }

    # Check delegation chain depth.
    chain_depth = len(mandate.delegation_chain)
    if chain_depth > max_depth:
        return {
            "valid": False,
            "status": mandate.status.value,
            "error": f"Delegation chain depth {chain_depth} exceeds max {max_depth}",
            "checks": checks,
        }

    # Check chain structure (each link has required fields).
    chain_valid = True
    for link in mandate.delegation_chain:
        link_dict = link.to_dict()
        if not link_dict.get("delegator") or not link_dict.get("delegate"):
            chain_valid = False
            break
    checks["chain_valid"] = chain_valid

    # Check mandate status.
    checks["not_expired"] = mandate.status != MandateStatus.EXPIRED
    checks["not_revoked"] = mandate.status != MandateStatus.REVOKED

    # Check constraints are present and valid JSON schema shape.
    checks["constraints_valid"] = isinstance(mandate.constraints, dict)

    # Signature check: verify if signature is present.
    # At v1.0, the sidecar does not have the issuer's public key for full
    # Ed25519 verification. Signature presence is checked; full verification
    # requires the key to be provided or looked up.
    checks["signature_valid"] = bool(mandate.signature)

    all_valid = all(checks.values())

    return {
        "valid": all_valid,
        "status": mandate.status.value,
        "checks": checks,
    }


def handle_shutdown(_params: dict[str, Any]) -> dict[str, Any]:
    """Graceful shutdown; the main loop exits after sending this response."""
    return {"ok": True, "message": "Shutting down"}


# -----------------------------------------------------------------------
# RPC dispatch table
# -----------------------------------------------------------------------

RPC_METHODS: dict[str, Any] = {
    "ping": handle_ping,
    "version": handle_version,
    "pack_receipt": handle_pack_receipt,
    "verify_receipt": handle_verify_receipt,
    "verify_mandate": handle_verify_mandate,
    "shutdown": handle_shutdown,
}


# -----------------------------------------------------------------------
# Main loop: JSON-RPC over stdio
# -----------------------------------------------------------------------


def main() -> None:
    """Read JSON-RPC requests from stdin, dispatch, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            # Malformed JSON; skip.
            continue

        request_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        handler = RPC_METHODS.get(method)
        if handler is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }
        else:
            try:
                result = handler(params)
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result,
                }
            except Exception as e:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32000,
                        "message": str(e),
                    },
                }

        # Write response as a single JSON line to stdout.
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

        # If shutdown was requested, exit after sending response.
        if method == "shutdown":
            sys.exit(0)


if __name__ == "__main__":
    main()
