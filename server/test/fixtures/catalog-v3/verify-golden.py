"""Independent stdlib verifier for the portable catalog-v3 parity corpus.

This intentionally shares no TypeScript implementation code. It checks every
corpus row, including canonical bytes, SHA-256, Ed25519 signatures, closed body
semantics, raw JSON refusals, and the generated signing-size boundary.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


HERE = Path(__file__).parent
CATALOG_BYTES = (HERE / "catalog-body-golden.json").read_bytes()
CORPUS_BYTES = (HERE / "wire-boundaries-golden.json").read_bytes()
if hashlib.sha256(CATALOG_BYTES).hexdigest() != "c90d86729aa42a8e0e997fbdbcc9767f55c1d26d02f5b9cbde3fb4ba6efbbc93":
    raise RuntimeError("catalog fixture digest mismatch")
if hashlib.sha256(CORPUS_BYTES).hexdigest() != "dc005d59de4fdbf4aff2b1a1b7c21e0c28d9606f0e3e6289ed24f9a658dbc767":
    raise RuntimeError("corpus fixture digest mismatch")
CATALOG = json.loads(CATALOG_BYTES)
CORPUS = json.loads(CORPUS_BYTES)
SPDX_DIR = HERE.parents[2] / "src" / "intelligence" / "catalog-v3" / "spdx"
SPDX_ABNF_BYTES = (SPDX_DIR / "spdx-expression-3.0.1.abnf").read_bytes()
if hashlib.sha256(SPDX_ABNF_BYTES).hexdigest() != "f449ffcf2e6d206442c11b77f8d47568a8ac5f0abeeb01eec16d68fceccb68fe":
    raise RuntimeError("SPDX expression grammar digest mismatch")
SPDX_TABLE_SOURCE = (SPDX_DIR / "spdx-tables.generated.ts").read_text("utf-8")
SPDX_PROJECTION_BYTES = (SPDX_DIR / "spdx-id-status-projection.v1.json").read_bytes()
if hashlib.sha256(SPDX_PROJECTION_BYTES).hexdigest() != "a9517d7e516498a8adec3c07fa95cc6702c80c88e9d7381f1b667bfbf92c1c5e":
    raise RuntimeError("SPDX fact projection digest mismatch")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


SPDX_PROJECTION = json.loads(SPDX_PROJECTION_BYTES, object_pairs_hook=reject_duplicate_keys)
if (
    not isinstance(SPDX_PROJECTION, dict)
    or set(SPDX_PROJECTION) != {
        "schema", "license_list_version", "release_date", "licenses", "exceptions",
    }
    or SPDX_PROJECTION["schema"] != "sanctuary.spdx-id-status-projection.v1"
    or SPDX_PROJECTION["license_list_version"] != "3.28.0"
    or SPDX_PROJECTION["release_date"] != "2026-02-20T00:00:00Z"
):
    raise RuntimeError("SPDX fact projection shape/version mismatch")


def validate_projection_rows(name: str, expected_count: int) -> list[list[Any]]:
    rows = SPDX_PROJECTION[name]
    if not isinstance(rows, list) or len(rows) != expected_count:
        raise RuntimeError(f"SPDX {name} projection count mismatch")
    previous: str | None = None
    seen: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or not isinstance(row[0], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}", row[0]) is None
            or not isinstance(row[1], bool)
        ):
            raise RuntimeError(f"SPDX {name} projection row mismatch")
        folded = row[0].lower()
        if folded in seen or (previous is not None and (previous.lower(), previous) >= (folded, row[0])):
            raise RuntimeError(f"SPDX {name} projection ordering/uniqueness mismatch")
        seen.add(folded)
        previous = row[0]
    return rows


SPDX_PROJECTED_LICENSE_ROWS = validate_projection_rows("licenses", 727)
SPDX_PROJECTED_EXCEPTION_ROWS = validate_projection_rows("exceptions", 84)


def generated_rows(name: str) -> list[list[Any]]:
    match = re.search(rf"^const {name}_MUTABLE = (.+) as const;$", SPDX_TABLE_SOURCE, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing generated SPDX rows: {name}")
    rows = json.loads(match.group(1))
    if not isinstance(rows, list):
        raise RuntimeError(f"invalid generated SPDX rows: {name}")
    return rows


SPDX_LICENSE_ROWS = generated_rows("SPDX_GENERATED_LICENSE_ROWS")
SPDX_EXCEPTION_ROWS = generated_rows("SPDX_GENERATED_EXCEPTION_ROWS")
if SPDX_LICENSE_ROWS != SPDX_PROJECTED_LICENSE_ROWS:
    raise RuntimeError("generated SPDX license rows differ from fact projection")
if SPDX_EXCEPTION_ROWS != SPDX_PROJECTED_EXCEPTION_ROWS:
    raise RuntimeError("generated SPDX exception rows differ from fact projection")
SPDX_TABLE_DIGEST = hashlib.sha256(json.dumps({
    "exceptions": SPDX_EXCEPTION_ROWS,
    "licenses": SPDX_LICENSE_ROWS,
}, separators=(",", ":")).encode()).hexdigest()
if SPDX_TABLE_DIGEST != "57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1":
    raise RuntimeError("generated SPDX table digest mismatch")
SPDX_LICENSES = {
    item[0].lower(): (item[0], item[1]) for item in SPDX_LICENSE_ROWS
}
SPDX_EXCEPTIONS = {
    item[0].lower(): (item[0], item[1]) for item in SPDX_EXCEPTION_ROWS
}
if len(SPDX_LICENSES) != len(SPDX_LICENSE_ROWS):
    raise RuntimeError("generated SPDX licenses contain case-fold duplicates")
if len(SPDX_EXCEPTIONS) != len(SPDX_EXCEPTION_ROWS):
    raise RuntimeError("generated SPDX exceptions contain case-fold duplicates")


def spdx_rows_casefold_unique(rows: list[list[Any]]) -> bool:
    return len({row[0].lower() for row in rows}) == len(rows)


if not spdx_rows_casefold_unique(SPDX_LICENSE_ROWS) or not spdx_rows_casefold_unique(SPDX_EXCEPTION_ROWS):
    raise RuntimeError("generated SPDX rows fail case-fold uniqueness")
if spdx_rows_casefold_unique([["MIT", False], ["mit", False]]):
    raise RuntimeError("case-fold uniqueness negative is ineffective")
SURFACES = [
    "concierge", "direct-agent-gate-advisor", "sentinel-scoring",
    "gate-explanation", "privacy-filter-tier-2", "template-suggestion",
]
DOMAINS = {
    "sanctuary.model-catalog.v3",
    "sanctuary.model-catalog-index.v1",
    "sanctuary.model-overlay.v1",
}
ZERO_DIGEST = "0" * 64
MAX_VERSION = 2_147_483_647
MAX_SAFE_INTEGER = 9_007_199_254_740_991
COMPONENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")
BINDING_ID = re.compile(r"(?!0{32}$)[0-9a-f]{32}")
CATALOG_KEY_ID = re.compile(r"cat-epoch-[1-9][0-9]{0,8}")
OVERLAY_KEY_ID = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
SOURCE_URL = re.compile(r"https://[a-z0-9.-]{1,253}(?::[0-9]{1,5})?/[A-Za-z0-9._~%!$&'()*+,;=:@/-]{0,246}")
ASCII_TEXT = re.compile(r"[\x20-\x7e]+")
LICENSE_REF = re.compile(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+")
ADDITION_REF = re.compile(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?AdditionRef-[A-Za-z0-9.-]+")
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
TIER_TABLE = {
    "schema": "tier-table.v1",
    "tiers": {
        "baseline": {"min_ram_gib": 8, "description": "Baseline local model hardware"},
        "mid": {"min_ram_gib": 16, "description": "Mid-tier local model hardware"},
        "pro": {"min_ram_gib": 32, "description": "Pro local model hardware"},
    },
}
SURFACE_DEFAULTS = {
    "schema": "surface-defaults.v1",
    "defaults": {
        "concierge": {"tier": "baseline", "assurance": "light"},
        "direct-agent-gate-advisor": {"tier": "baseline", "assurance": "light"},
        "sentinel-scoring": {"tier": "mid", "assurance": "immune"},
        "gate-explanation": {"tier": "baseline", "assurance": "light"},
        "privacy-filter-tier-2": {"tier": "mid", "assurance": "immune"},
        "template-suggestion": {"tier": "baseline", "assurance": "light"},
    },
}
COMPILED_SURFACE_ASSURANCE_FLOOR = {
    "concierge": "light",
    "direct-agent-gate-advisor": "light",
    "sentinel-scoring": "immune",
    "gate-explanation": "light",
    "privacy-filter-tier-2": "immune",
    "template-suggestion": "light",
}
KEY_EPOCH_KEYS = {
    "epoch", "signing_key_id", "pubkey", "min_catalog_version",
    "max_catalog_version", "min_index_version", "max_index_version", "status",
}


class VerificationFailure(RuntimeError):
    pass


def require(condition: bool, label: str) -> None:
    if not condition:
        raise VerificationFailure(label)


def b64url_decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value) or len(value) % 4 == 1:
        raise ValueError("bad_signature_encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("bad_signature_encoding")
    return raw


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def recover_x(y: int, sign: int) -> int:
    if y >= P:
        raise ValueError("bad point")
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P or (x == 0 and sign):
        raise ValueError("bad point")
    return P - x if (x & 1) != sign else x


Point = tuple[int, int]


def decode_point(raw: bytes) -> Point:
    if len(raw) != 32:
        raise ValueError("bad point")
    encoded = int.from_bytes(raw, "little")
    y = encoded & ((1 << 255) - 1)
    return recover_x(y, encoded >> 255), y


def add(left: Point, right: Point) -> Point:
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2 % P
    return (
        (x1 * y2 + x2 * y1) * pow(1 + product, P - 2, P) % P,
        (y1 * y2 + x1 * x2) * pow(1 - product, P - 2, P) % P,
    )


def multiply(point: Point, scalar: int) -> Point:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE = (recover_x(BASE_Y, 0), BASE_Y)
IDENTITY = (0, 1)


def encode_point(point: Point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_STRICT_PUBLIC_POINT_CACHE: dict[bytes, bool] = {}


def strict_public_point(point: Point) -> bool:
    # Memoized on the point's canonical encoded-bytes form: the parity corpus reuses
    # the same handful of public keys and signature R-values across ~56 verify calls
    # (at most 4 distinct points), and each check costs two full scalar
    # multiplications (the order-8 and order-L tests below); caching the verdict for
    # a point already proven avoids re-deriving it identically every call. The cache
    # never changes the boolean this function returns, only whether it is recomputed.
    key = encode_point(point)
    cached = _STRICT_PUBLIC_POINT_CACHE.get(key)
    if cached is not None:
        return cached
    result = multiply(point, 8) != IDENTITY and multiply(point, L) == IDENTITY
    _STRICT_PUBLIC_POINT_CACHE[key] = result
    return result


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = decode_point(public_key)
        r_point = decode_point(signature[:32])
    except ValueError:
        return False
    if not strict_public_point(public_point) or not strict_public_point(r_point):
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % L
    return multiply(BASE, scalar) == add(r_point, multiply(public_point, challenge))


def utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        value.encode("utf-8")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            canonical_json(key) + ":" + canonical_json(value[key])
            for key in sorted(value, key=utf16_sort_key)
        ) + "}"
    raise TypeError("non-canonical JSON value")


def key_error(value: Any, required: set[str], optional: set[str] | None = None) -> str | None:
    if not isinstance(value, dict):
        return "invalid_type"
    optional = optional or set()
    if not required.issubset(value):
        return "missing_key"
    if not set(value).issubset(required | optional):
        return "unknown_key"
    return None


def exact_keys(value: Any, required: set[str]) -> bool:
    return key_error(value, required) is None


def positive_version(value: Any) -> bool:
    return type(value) is int and 1 <= value <= MAX_VERSION


def positive_safe_integer(value: Any) -> bool:
    return type(value) is int and 1 <= value <= MAX_SAFE_INTEGER


def timestamp(value: Any) -> bool:
    match = re.fullmatch(
        r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z",
        value if isinstance(value, str) else "",
    )
    if not match:
        return False
    year, month, day, hour, minute, second = map(int, match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= month <= 12 and 1 <= day <= month_days[month - 1] and hour < 24 and minute < 60 and second < 60


def digest(value: Any, *, nonzero: bool = False) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None and (not nonzero or value != ZERO_DIGEST)


def identity(value: Any) -> bool:
    keys = {"registry", "namespace", "model", "tag", "ollama_manifest_sha256"}
    return exact_keys(value, keys) and value["registry"] == "registry.ollama.ai" and all(
        isinstance(value[key], str) and COMPONENT.fullmatch(value[key])
        for key in ("namespace", "model", "tag")
    ) and digest(value["ollama_manifest_sha256"], nonzero=True)


def canonical_user_ref(value: str) -> str:
    match = re.fullmatch(
        r"(?:(DocumentRef-)([A-Za-z0-9.-]+):)?(LicenseRef-|AdditionRef-)([A-Za-z0-9.-]+)",
        value,
    )
    if match is None:
        raise VerificationFailure("invalid SPDX user reference")
    document = f"DocumentRef-{match.group(2).lower()}:" if match.group(2) else ""
    return f"{document}{match.group(3)}{match.group(4).lower()}"


def tokenize_spdx(source: str) -> list[tuple[str, str]] | None:
    tokens: list[tuple[str, str]] = []
    cursor = 0
    while cursor < len(source):
        if source[cursor] in " \t":
            cursor += 1
            continue
        if source[cursor] in "()":
            tokens.append(("lparen" if source[cursor] == "(" else "rparen", source[cursor]))
            cursor += 1
            continue
        end = cursor
        while end < len(source) and source[end] not in " \t()":
            end += 1
        text = source[cursor:end]
        if not text or "\r" in text or "\n" in text:
            return None
        kind = "op" if text in {"AND", "and", "OR", "or", "WITH", "with"} else "atom"
        if kind == "op" and (
            cursor == 0 or end == len(source)
            or source[cursor - 1] not in " \t" or source[end] not in " \t"
        ):
            return None
        tokens.append((kind, text))
        cursor = end
    return tokens


class SpdxParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.cursor = 0

    def peek(self, *texts: str) -> tuple[str, str] | None:
        if self.cursor >= len(self.tokens):
            return None
        token = self.tokens[self.cursor]
        return token if not texts or token[1] in texts else None

    def take(self) -> tuple[str, str] | None:
        token = self.peek()
        self.cursor += 1
        return token

    def parse(self) -> str | None:
        value = self.parse_or()
        return value if value is not None and self.cursor == len(self.tokens) else None

    def parse_or(self) -> str | None:
        left = self.parse_and()
        if left is None:
            return None
        while self.peek("OR", "or"):
            self.take()
            right = self.parse_and()
            if right is None:
                return None
            left = f"{left} OR {right}"
        return left

    def parse_and(self) -> str | None:
        left = self.parse_with()
        if left is None:
            return None
        while self.peek("AND", "and"):
            self.take()
            right = self.parse_with()
            if right is None:
                return None
            left = f"{left} AND {right}"
        return left

    def parse_with(self) -> str | None:
        left = self.parse_primary()
        if left is None:
            return None
        if not self.peek("WITH", "with"):
            return left
        if left.startswith("("):
            return None
        self.take()
        token = self.take()
        if token is None or token[0] != "atom":
            return None
        exception_entry = SPDX_EXCEPTIONS.get(token[1].lower())
        exception = exception_entry[0] if exception_entry and not exception_entry[1] else None
        addition = canonical_user_ref(token[1]) if ADDITION_REF.fullmatch(token[1]) else None
        return f"{left} WITH {exception or addition}" if exception or addition else None

    def parse_primary(self) -> str | None:
        if self.peek() and self.peek()[0] == "lparen":
            self.take()
            nested = self.parse_or()
            if nested is None or not self.peek() or self.peek()[0] != "rparen":
                return None
            self.take()
            return f"({nested})"
        token = self.take()
        if token is None or token[0] != "atom":
            return None
        plus = token[1].endswith("+")
        atom = token[1][:-1] if plus else token[1]
        listed = SPDX_LICENSES.get(atom.lower())
        if listed and not listed[1]:
            return listed[0] + ("+" if plus else "")
        if not plus and LICENSE_REF.fullmatch(atom):
            return canonical_user_ref(atom)
        return None


def parse_spdx(value: Any) -> tuple[str, str | None]:
    if (
        not isinstance(value, str) or value == "custom" or not value
        or len(value) > 128 or len(value.encode()) > 128
        or value.strip() != value or "\r" in value or "\n" in value
    ):
        return "invalid_spdx", None
    tokens = tokenize_spdx(value)
    if not tokens:
        return "invalid_spdx", None
    canonical = SpdxParser(tokens).parse()
    return ("accept", canonical) if canonical is not None else ("invalid_spdx", None)


def validate_identity(value: Any) -> str:
    keys = {"registry", "namespace", "model", "tag", "ollama_manifest_sha256"}
    error = key_error(value, keys)
    if error:
        return error
    if value["registry"] != "registry.ollama.ai":
        return "invalid_value"
    if any(not isinstance(value[key], str) or not COMPONENT.fullmatch(value[key]) for key in ("namespace", "model", "tag")):
        return "invalid_value"
    return "accept" if digest(value["ollama_manifest_sha256"], nonzero=True) else "invalid_value"


def valid_source_url(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or not ASCII_TEXT.fullmatch(value):
        return False
    if not SOURCE_URL.fullmatch(value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    hostname = parsed.hostname or ""
    raw_authority = value[len("https://"):value.index("/", len("https://"))]
    raw_hostname = re.sub(r":[0-9]{1,5}$", "", raw_authority)
    port_text = parsed.netloc.rsplit(":", 1)[1] if ":" in parsed.netloc else None
    canonical_authority = hostname if port is None else f"{hostname}:{port}"
    labels = hostname.split(".")
    try:
        ipaddress.ip_address(hostname)
        numeric_host = True
    except ValueError:
        numeric_host = False
    valid_percent_escapes = all(
        character != "%" or re.fullmatch(r"[0-9A-F]{2}", parsed.path[index + 1:index + 3]) is not None
        for index, character in enumerate(parsed.path)
    )
    try:
        decoded_segments = [unquote(segment, errors="strict") for segment in parsed.path.split("/")]
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and bool(parsed.path)
        and hostname == raw_hostname
        and hostname == hostname.lower()
        and not numeric_host
        and 2 <= len(labels)
        and all(
            1 <= len(label) <= 63
            and not label.startswith("xn--")
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is not None
            for label in labels
        )
        and re.fullmatch(r"[a-z]{2,63}", labels[-1]) is not None
        and (port is None or 1 <= port <= 65_535)
        and (port_text is None or port_text == str(port))
        and port != 443
        and valid_percent_escapes
        and all(
            segment not in {".", ".."}
            and re.search(r"[\\/\x00-\x1f\x7f]", segment) is None
            for segment in decoded_segments
        )
        and value == f"https://{canonical_authority}{parsed.path}"
    )


def validate_license(value: Any) -> str:
    required = {"spdx", "source_url", "evidence_sha256"}
    error = key_error(value, required, {"custom_name"})
    if error:
        return error
    if (
        not isinstance(value["spdx"], str)
        or not valid_source_url(value["source_url"])
        or not digest(value["evidence_sha256"], nonzero=True)
    ):
        return "invalid_value"
    if value["spdx"] == "custom":
        custom = value.get("custom_name")
        return "accept" if (
            isinstance(custom, str) and 1 <= len(custom) <= 120 and ASCII_TEXT.fullmatch(custom)
        ) else "invalid_value"
    if "custom_name" in value:
        return "unknown_key"
    verdict, canonical = parse_spdx(value["spdx"])
    return verdict if verdict != "accept" or canonical == value["spdx"] else "invalid_spdx"


def validate_tier_table(value: Any) -> str:
    error = key_error(value, {"schema", "tiers"})
    if error:
        return error
    if value["schema"] != "tier-table.v1" or not isinstance(value["tiers"], dict):
        return "invalid_value"
    error = key_error(value["tiers"], {"baseline", "mid", "pro"})
    if error:
        return error
    thresholds: list[int] = []
    for name in ("baseline", "mid", "pro"):
        spec = value["tiers"][name]
        error = key_error(spec, {"min_ram_gib", "description"})
        if error:
            return error
        if (
            type(spec["min_ram_gib"]) is not int
            or not 1 <= spec["min_ram_gib"] <= 4096
            or not isinstance(spec["description"], str)
            or not 1 <= len(spec["description"]) <= 120
            or not ASCII_TEXT.fullmatch(spec["description"])
        ):
            return "invalid_value"
        thresholds.append(spec["min_ram_gib"])
    return "accept" if thresholds[0] < thresholds[1] < thresholds[2] else "invalid_order"


def validate_surface_defaults(value: Any) -> str:
    error = key_error(value, {"schema", "defaults"})
    if error:
        return error
    if value["schema"] != "surface-defaults.v1" or not isinstance(value["defaults"], dict):
        return "invalid_value"
    error = key_error(value["defaults"], set(SURFACES))
    if error:
        return error
    for surface in SURFACES:
        default = value["defaults"][surface]
        error = key_error(default, {"tier", "assurance"})
        if error:
            return error
        if default["tier"] not in {"baseline", "mid", "pro"} or default["assurance"] not in {"light", "immune"}:
            return "invalid_value"
    return "accept"


def identity_tuple(value: dict[str, Any]) -> str:
    return "\0".join(value[key] for key in ("registry", "namespace", "model", "tag"))


def runtime_tag(value: dict[str, Any]) -> str:
    return f'{value["namespace"]}/{value["model"]}:{value["tag"]}'


def validate_catalog(body: Any) -> str:
    keys = {"schema", "catalog_version", "issued_at", "source_commit", "previous_catalog_body_sha256", "models", "tiers", "surface_defaults"}
    error = key_error(body, keys)
    if error:
        return error
    if (
        body["schema"] != "sanctuary.model-catalog.v3"
        or not positive_version(body["catalog_version"])
        or not timestamp(body["issued_at"])
        or not isinstance(body["source_commit"], str)
        or not SOURCE_COMMIT.fullmatch(body["source_commit"])
    ):
        return "invalid_value"
    previous = body["previous_catalog_body_sha256"]
    if (body["catalog_version"] == 1 and previous is not None) or (
        body["catalog_version"] != 1 and not digest(previous, nonzero=True)
    ):
        return "invalid_value"
    if not isinstance(body["models"], list):
        return "invalid_type"
    if len(body["models"]) < 1:
        return "empty_collection"
    if len(body["models"]) > 32:
        return "too_many_entries"
    ids: set[str] = set()
    identities: set[str] = set()
    tags: set[str] = set()
    prior_id: str | None = None
    for model in body["models"]:
        error = key_error(model, {"model_id", "identity", "assurance", "license", "hardware_tier"})
        if error:
            return error
        if not isinstance(model["model_id"], str) or not COMPONENT.fullmatch(model["model_id"]):
            return "invalid_value"
        if prior_id is not None and model["model_id"] <= prior_id:
            return "duplicate_entry" if model["model_id"] == prior_id else "invalid_order"
        error = validate_identity(model["identity"])
        if error != "accept":
            return error
        if model["assurance"] not in {"light", "immune"}:
            return "invalid_value"
        error = validate_license(model["license"])
        if error != "accept":
            return error
        if model["hardware_tier"] not in {"baseline", "mid", "pro"}:
            return "invalid_value"
        tuple_key = identity_tuple(model["identity"])
        tag_key = runtime_tag(model["identity"])
        if model["model_id"] in ids or tuple_key in identities or tag_key in tags:
            return "duplicate_entry"
        ids.add(model["model_id"])
        identities.add(tuple_key)
        tags.add(tag_key)
        prior_id = model["model_id"]
    error = validate_tier_table(body["tiers"])
    if error != "accept":
        return error
    error = validate_surface_defaults(body["surface_defaults"])
    if error != "accept":
        return error
    if body["tiers"] != TIER_TABLE or body["surface_defaults"] != SURFACE_DEFAULTS:
        return "invalid_value"
    size = len((body["schema"] + "\n" + canonical_json(body)).encode())
    return "accept" if size <= 32768 else "manifest_too_large"


def validate_surface_list(value: Any) -> str:
    if not isinstance(value, list):
        return "invalid_type"
    if len(value) < 1:
        return "empty_collection"
    if len(value) > len(SURFACES):
        return "too_many_entries"
    ranks: list[int] = []
    for item in value:
        if item not in SURFACES:
            return "invalid_value"
        rank = SURFACES.index(item)
        if ranks and rank <= ranks[-1]:
            return "duplicate_entry" if rank == ranks[-1] else "invalid_order"
        ranks.append(rank)
    return "accept"


def validate_overlay(body: Any) -> str:
    keys = {"schema", "overlay_version", "overlay_binding_id", "issued_at", "entries"}
    error = key_error(body, keys)
    if error:
        return error
    if (
        body["schema"] != "sanctuary.model-overlay.v1"
        or not positive_version(body["overlay_version"])
        or not isinstance(body["overlay_binding_id"], str)
        or not BINDING_ID.fullmatch(body["overlay_binding_id"])
        or not timestamp(body["issued_at"])
    ):
        return "invalid_value"
    if not isinstance(body["entries"], list):
        return "invalid_type"
    if len(body["entries"]) > 64:
        return "too_many_entries"
    ids: set[str] = set()
    identities: set[str] = set()
    tags: set[str] = set()
    prior_id: str | None = None
    for entry in body["entries"]:
        error = key_error(entry, {"model_id", "identity", "assurance", "surface_authorization"})
        if error:
            return error
        if not isinstance(entry["model_id"], str) or not COMPONENT.fullmatch(entry["model_id"]):
            return "invalid_value"
        if prior_id is not None and entry["model_id"] <= prior_id:
            return "duplicate_entry" if entry["model_id"] == prior_id else "invalid_order"
        error = validate_identity(entry["identity"])
        if error != "accept":
            return error
        if entry["assurance"] not in {"light", "immune"}:
            return "invalid_value"
        error = validate_surface_list(entry["surface_authorization"])
        if error != "accept":
            return error
        tuple_key = identity_tuple(entry["identity"])
        tag_key = runtime_tag(entry["identity"])
        if entry["model_id"] in ids or tuple_key in identities or tag_key in tags:
            return "duplicate_entry"
        ids.add(entry["model_id"])
        identities.add(tuple_key)
        tags.add(tag_key)
        prior_id = entry["model_id"]
    size = len((body["schema"] + "\n" + canonical_json(body)).encode())
    return "accept" if size <= 32768 else "manifest_too_large"


def validate_index(body: Any) -> str:
    keys = {"schema", "index_version", "previous_index_body_sha256", "segment_number", "segment_base_index_version", "first_catalog_version", "highest_catalog_version", "issued_at", "entries"}
    error = key_error(body, keys)
    if error:
        return error
    if (
        body["schema"] != "sanctuary.model-catalog-index.v1"
        or not positive_version(body["index_version"])
        or not positive_version(body["segment_number"])
        or not positive_version(body["segment_base_index_version"])
        or body["segment_base_index_version"] > body["index_version"]
        or not positive_version(body["first_catalog_version"])
        or not positive_version(body["highest_catalog_version"])
        or not timestamp(body["issued_at"])
    ):
        return "invalid_value"
    previous = body["previous_index_body_sha256"]
    if (body["index_version"] == 1 and previous is not None) or (
        body["index_version"] != 1 and not digest(previous, nonzero=True)
    ):
        return "invalid_value"
    entries = body["entries"]
    if not isinstance(entries, list):
        return "invalid_type"
    if len(entries) < 1:
        return "empty_collection"
    if len(entries) > 64:
        return "too_many_entries"
    versions: list[int] = []
    release_ids: set[int] = set()
    asset_ids: set[int] = set()
    asset_digests: set[str] = set()
    for entry in entries:
        error = key_error(entry, {"catalog_version", "catalog_release_id", "catalog_asset_id", "envelope_sha256", "body_sha256", "catalog_key_epoch"})
        if error:
            return error
        if (
            not positive_version(entry["catalog_version"])
            or not positive_safe_integer(entry["catalog_release_id"])
            or not positive_safe_integer(entry["catalog_asset_id"])
            or not digest(entry["envelope_sha256"], nonzero=True)
            or not digest(entry["body_sha256"], nonzero=True)
            or not positive_version(entry["catalog_key_epoch"])
        ):
            return "invalid_value"
        if versions and entry["catalog_version"] != versions[-1] + 1:
            return "invalid_order"
        if (
            entry["envelope_sha256"] == entry["body_sha256"]
            or entry["catalog_release_id"] in release_ids
            or entry["catalog_asset_id"] in asset_ids
            or entry["envelope_sha256"] in asset_digests
            or entry["body_sha256"] in asset_digests
        ):
            return "duplicate_entry"
        release_ids.add(entry["catalog_release_id"])
        asset_ids.add(entry["catalog_asset_id"])
        asset_digests.add(entry["envelope_sha256"])
        asset_digests.add(entry["body_sha256"])
        versions.append(entry["catalog_version"])
    if versions[0] != body["first_catalog_version"] or versions[-1] != body["highest_catalog_version"]:
        return "invalid_value"
    if (
        body["first_catalog_version"] != body["segment_base_index_version"]
        or body["highest_catalog_version"] != body["index_version"]
        or len(entries) != body["index_version"] - body["segment_base_index_version"] + 1
        or body["segment_number"] > body["segment_base_index_version"]
        or ((body["segment_number"] == 1) != (body["segment_base_index_version"] == 1))
    ):
        return "invalid_value"
    size = len((body["schema"] + "\n" + canonical_json(body)).encode())
    return "accept" if size <= 32768 else "manifest_too_large"


def validate_keyring(keyring: Any) -> str:
    if not isinstance(keyring, list) or not keyring:
        return "invalid_value"
    decoded_keys: set[bytes] = set()
    prior: dict[str, Any] | None = None
    for index, epoch in enumerate(keyring):
        if not exact_keys(epoch, KEY_EPOCH_KEYS):
            return "invalid_value"
        if (
            epoch["epoch"] != index + 1
            or epoch["signing_key_id"] != f"cat-epoch-{epoch['epoch']}"
            or not positive_version(epoch["min_catalog_version"])
            or not positive_version(epoch["min_index_version"])
            or epoch["status"] not in {"active", "retired", "revoked"}
            or not isinstance(epoch["pubkey"], str)
        ):
            return "invalid_value"
        try:
            public_key = b64url_decode(epoch["pubkey"])
            public_point = decode_point(public_key)
        except ValueError:
            return "invalid_value"
        if len(public_key) != 32 or not any(public_key) or not strict_public_point(public_point):
            return "invalid_value"
        if public_key in decoded_keys:
            return "invalid_value"
        decoded_keys.add(public_key)
        last = index == len(keyring) - 1
        if (
            last != (epoch["status"] == "active")
            or last != (epoch["max_catalog_version"] is None)
            or last != (epoch["max_index_version"] is None)
        ):
            return "invalid_value"
        if not last and (
            not positive_version(epoch["max_catalog_version"])
            or epoch["max_catalog_version"] < epoch["min_catalog_version"]
            or not positive_version(epoch["max_index_version"])
            or epoch["max_index_version"] < epoch["min_index_version"]
        ):
            return "invalid_value"
        if prior is not None and (
            epoch["min_catalog_version"] != prior["max_catalog_version"] + 1
            or epoch["min_index_version"] != prior["max_index_version"] + 1
        ):
            return "invalid_value"
        prior = epoch
    return "accept"


def resolve_catalog_key(
    keyring: Any,
    key_id: str,
    version: int,
    kind: str,
) -> tuple[str, bytes | None]:
    verdict = validate_keyring(keyring)
    if verdict != "accept":
        return verdict, None
    epoch = next((candidate for candidate in keyring if candidate["signing_key_id"] == key_id), None)
    if epoch is None:
        return "unknown_signing_key", None
    if epoch["status"] == "revoked":
        return "signing_key_revoked", None
    minimum = epoch["min_catalog_version"] if kind == "catalog" else epoch["min_index_version"]
    maximum = epoch["max_catalog_version"] if kind == "catalog" else epoch["max_index_version"]
    if version < minimum or (maximum is not None and version > maximum):
        return "signing_key_out_of_range", None
    return "accept", b64url_decode(epoch["pubkey"])


_AUTHENTICATED_COMBINATION = object()


def validate_catalog_overlay_combination(
    catalog: Any,
    overlay: Any,
    expected_binding_id: Any,
    minimum_overlay_version_exclusive: Any,
    authority: object | None = None,
) -> str:
    if authority is not _AUTHENTICATED_COMBINATION:
        return "unauthenticated_input"
    verdict = validate_catalog(catalog)
    if verdict != "accept":
        return verdict
    verdict = validate_overlay(overlay)
    if verdict != "accept":
        return verdict
    if not isinstance(expected_binding_id, str) or not BINDING_ID.fullmatch(expected_binding_id):
        return "invalid_value"
    if type(minimum_overlay_version_exclusive) is not int or minimum_overlay_version_exclusive < 0:
        return "invalid_value"
    if overlay["overlay_version"] <= minimum_overlay_version_exclusive:
        return "overlay_rollback"
    if overlay["overlay_binding_id"] != expected_binding_id:
        return "overlay_binding_mismatch"
    catalog_ids = {model["model_id"] for model in catalog["models"]}
    catalog_identities = {identity_tuple(model["identity"]) for model in catalog["models"]}
    catalog_tags = {runtime_tag(model["identity"]) for model in catalog["models"]}
    ranks = {"light": 0, "immune": 1}
    for entry in overlay["entries"]:
        if (
            entry["model_id"] in catalog_ids
            or identity_tuple(entry["identity"]) in catalog_identities
            or runtime_tag(entry["identity"]) in catalog_tags
        ):
            return "overlay_collision"
        for surface in entry["surface_authorization"]:
            configured = catalog["surface_defaults"]["defaults"][surface]["assurance"]
            floor = max(configured, COMPILED_SURFACE_ASSURANCE_FLOOR[surface], key=ranks.__getitem__)
            if ranks[entry["assurance"]] < ranks[floor]:
                return "overlay_escalation"
    return "accept"


def boundary(name: str) -> dict[str, Any]:
    return next(item for item in CORPUS["boundaries"] if item["name"] == name)


def body_for(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("external_fixture") == "catalog-body-golden.json":
        return copy.deepcopy(CATALOG["body"])
    return copy.deepcopy(item["body"])


def envelope_for(item: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    signature = item.get("signature", CATALOG["signature"])
    return {"body": body, "signature": signature, item["key_field"]: item["key_id"]}


def set_path(root: Any, path: list[Any], value: Any) -> None:
    cursor = root
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = copy.deepcopy(value)


def delete_path(root: Any, path: list[Any]) -> None:
    cursor = root
    for key in path[:-1]:
        cursor = cursor[key]
    del cursor[path[-1]]


def noncanonical_signature(value: str) -> str:
    raw = bytearray(b64url_decode(value))
    scalar = int.from_bytes(raw[32:], "little") + L
    raw[32:] = scalar.to_bytes(32, "little")
    return b64url_encode(raw)


def validate_envelope(item: dict[str, Any], envelope: Any) -> str:
    key_name = item["key_field"]
    error = key_error(envelope, {"body", "signature", key_name})
    if error:
        return error
    body_verdict = validate_body(item["domain"], envelope["body"])
    if body_verdict != "accept":
        return body_verdict
    key_pattern = OVERLAY_KEY_ID if key_name == "signer_key_id" else CATALOG_KEY_ID
    if (
        not isinstance(envelope["signature"], str)
        or not isinstance(envelope[key_name], str)
        or not key_pattern.fullmatch(envelope[key_name])
    ):
        return "invalid_value"
    if len(envelope["signature"]) != 86:
        return "bad_signature_length"
    try:
        signature = b64url_decode(envelope["signature"])
    except ValueError as error:
        return str(error)
    if len(signature) != 64:
        return "bad_signature_length"
    if not any(signature):
        return "zero_signature"
    if key_name == "signer_key_id":
        expected_key_id = b64url_encode(hashlib.sha256(b64url_decode(CORPUS["test_public_key"])).digest())
        if envelope[key_name] != expected_key_id:
            return "unknown_signing_key"
        public_key = b64url_decode(CORPUS["test_public_key"])
    else:
        kind = "catalog" if item["domain"] == "sanctuary.model-catalog.v3" else "index"
        version = envelope["body"]["catalog_version" if kind == "catalog" else "index_version"]
        verdict, resolved_key = resolve_catalog_key(
            CORPUS["test_catalog_keyring"], envelope[key_name], version, kind,
        )
        if verdict != "accept":
            return verdict
        public_key = resolved_key
    message = (item["domain"] + "\n" + canonical_json(envelope["body"])).encode()
    if public_key is None:
        raise VerificationFailure("resolved signing key")
    if not verify_ed25519(public_key, signature, message):
        return "bad_signature"
    if key_name == "signing_key_id" and item["domain"] == "sanctuary.model-catalog-index.v1":
        for entry in envelope["body"]["entries"]:
            verdict, _entry_key = resolve_catalog_key(
                CORPUS["test_catalog_keyring"],
                f"cat-epoch-{entry['catalog_key_epoch']}",
                entry["catalog_version"],
                "catalog",
            )
            if verdict != "accept":
                return verdict
    return "accept"


def validate_body(domain: str, body: Any) -> str:
    if domain == "sanctuary.model-catalog.v3":
        return validate_catalog(body)
    if domain == "sanctuary.model-catalog-index.v1":
        return validate_index(body)
    if domain == "sanctuary.model-overlay.v1":
        return validate_overlay(body)
    return "invalid_value"


def apply_structural_mutation(body: dict[str, Any], item: dict[str, Any], mutation: str | None) -> None:
    if mutation == "append_index_gap":
        gap = copy.deepcopy(body["entries"][0])
        gap.update(catalog_version=3, catalog_release_id=1003, catalog_asset_id=2003)
        body["entries"].append(gap)
        body["highest_catalog_version"] = 3
    elif isinstance(mutation, str) and (
        mutation.startswith("append_index_duplicate_") or mutation == "append_index_cross_digest"
    ):
        first = body["entries"][0]
        second = {
            **copy.deepcopy(first),
            "catalog_version": 2,
            "catalog_release_id": 1002,
            "catalog_asset_id": 2002,
            "envelope_sha256": "5" * 64,
            "body_sha256": "6" * 64,
        }
        field = {
            "append_index_duplicate_release": "catalog_release_id",
            "append_index_duplicate_asset": "catalog_asset_id",
            "append_index_duplicate_envelope": "envelope_sha256",
            "append_index_duplicate_body": "body_sha256",
            "append_index_cross_digest": "body_sha256",
        }[mutation]
        second[field] = first["envelope_sha256"] if mutation == "append_index_cross_digest" else first[field]
        body["entries"].append(second)
        body["index_version"] = 2
        body["highest_catalog_version"] = 2
        body["previous_index_body_sha256"] = "a" * 64
    elif mutation == "append_duplicate_identity":
        field = "models" if item["domain"] == "sanctuary.model-catalog.v3" else "entries"
        duplicate = copy.deepcopy(body[field][0])
        duplicate["model_id"] = f"{body[field][-1]['model_id']}z"
        body[field].append(duplicate)
    elif mutation == "overflow_collection":
        if item["domain"] == "sanctuary.model-catalog-index.v1":
            template = body["entries"][0]
            body["entries"] = [
                {
                    **copy.deepcopy(template),
                    "catalog_version": index + 1,
                    "catalog_release_id": 1001 + index,
                    "catalog_asset_id": 2001 + index,
                }
                for index in range(65)
            ]
            body["highest_catalog_version"] = 65
        else:
            field = "models" if item["domain"] == "sanctuary.model-catalog.v3" else "entries"
            limit = 33 if field == "models" else 65
            template = body[field][0]
            body[field] = []
            for index in range(limit):
                candidate = copy.deepcopy(template)
                candidate["model_id"] = f"m{index:02d}"
                candidate["identity"]["tag"] = f"t{index:02d}"
                body[field].append(candidate)


def execute_case(fixture: dict[str, Any]) -> str:
    item = boundary(fixture["boundary"])
    body = body_for(item)
    if "path" in fixture:
        set_path(body, fixture["path"], fixture.get("value"))
    if "delete_path" in fixture:
        delete_path(body, fixture["delete_path"])
    apply_structural_mutation(body, item, fixture.get("mutation"))
    envelope = envelope_for(item, body)
    if "envelope_path" in fixture:
        set_path(envelope, fixture["envelope_path"], fixture.get("envelope_value"))
    if "delete_envelope_path" in fixture:
        delete_path(envelope, fixture["delete_envelope_path"])
    if fixture.get("mutation") == "pad_signature":
        envelope["signature"] += "="
    if fixture.get("mutation") == "noncanonical_signature":
        envelope["signature"] = noncanonical_signature(envelope["signature"])
    if fixture.get("mutation") == "short_signature":
        envelope["signature"] = "AA"
    if fixture.get("mutation") == "zero_signature":
        envelope["signature"] = b64url_encode(bytes(64))

    if fixture["operation"] == "verify_signature":
        try:
            signature = b64url_decode(envelope["signature"])
        except ValueError as error:
            return str(error)
        domain = fixture.get("domain", item["domain"])
        if domain not in DOMAINS:
            return "invalid_value"
        message = (domain + "\n" + canonical_json(body)).encode()
        return "accept" if verify_ed25519(b64url_decode(CORPUS["test_public_key"]), signature, message) else "bad_signature"
    if fixture["operation"] == "parse_envelope":
        return validate_envelope(item, envelope)
    if fixture["operation"] == "parse_body":
        return validate_body(item["domain"], body)
    raise VerificationFailure(f"unknown contract operation: {fixture['operation']}")


def build_catalog_cap_body(target_bytes: int) -> dict[str, Any]:
    def component(prefix: str, index: int) -> str:
        return (prefix + str(index).zfill(2)).ljust(64, "x")

    body = copy.deepcopy(CATALOG["body"])
    body["catalog_version"] = 2_147_483_647
    body["previous_catalog_body_sha256"] = "b" * 64
    body["models"] = []
    for index in range(32):
        body["models"].append({
            "model_id": component("m", index),
            "identity": {
                "registry": "registry.ollama.ai", "namespace": component("n", index),
                "model": component("o", index), "tag": component("t", index),
                "ollama_manifest_sha256": str(index % 9 + 1) * 64,
            },
            "assurance": "immune",
            "license": {
                "spdx": "custom", "custom_name": "c" * 120,
                "source_url": "https://example.com/" + "a" * 236,
                "evidence_sha256": "a" * 64,
            },
            "hardware_tier": "baseline",
        })
    size = len((body["schema"] + "\n" + canonical_json(body)).encode())
    for model in body["models"]:
        while size > target_bytes and len(model["license"]["custom_name"]) > 1:
            model["license"]["custom_name"] = model["license"]["custom_name"][:-1]
            size -= 1
    require(size == target_bytes, f"catalog cap construction: {target_bytes}")
    return body


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in {"__proto__", "prototype", "constructor"}:
            raise ValueError("prototype_key")
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def reject_non_integer_number_lexemes(text: str) -> bool:
    in_string = False
    escaped = False
    cursor = 0
    while cursor < len(text):
        char = text[cursor]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            cursor += 1
            continue
        if char == '"':
            in_string = True
            cursor += 1
            continue
        if char == "-" or char in "0123456789":
            end = cursor + 1
            while end < len(text) and text[end] in "0123456789eE+.-":
                end += 1
            lexeme = text[cursor:end]
            if re.fullmatch(r"(?:0|[1-9][0-9]*)", lexeme) is None:
                return True
            cursor = end
            continue
        cursor += 1
    return False


def parse_catalog_json(text: Any, max_bytes: int) -> str:
    if type(max_bytes) is not int or max_bytes <= 0:
        return "invalid_value"
    bounded_max = min(max_bytes, 65_536)
    if not isinstance(text, str):
        return "invalid_type"
    if len(text) > bounded_max:
        return "manifest_too_large"
    if len(text.encode()) > bounded_max:
        return "manifest_too_large"
    if reject_non_integer_number_lexemes(text):
        return "invalid_value"
    try:
        json.loads(text, object_pairs_hook=reject_duplicate_pairs)
        return "accept"
    except ValueError as error:
        return str(error)


EXPECTED_CORPUS_KEYS = {
    "schema", "test_public_key", "derived_test_signer_key_id", "boundaries",
    "test_catalog_keyring", "spdx", "contract_cases", "generated_size_cases", "raw_adversarial",
}
EXPECTED_CORPUS_ROW_DIGESTS = {
    "boundaries": "f7cc089d23cbadd6b781a0210f04aac5112c74d18773647614854b31f7df8978",
    "spdx": "0b3aa9fe04852ae6a03a8ab0b90bada24db6f14a7f984a4c03840984f5b931b4",
    "contract_cases": "953f924e3346ad1dff3eddce1d715f2763acb670a7a0875c261a8019c16113ab",
    "generated_size_cases": "301b9509c8fa922f68e359b7e5c8a5425bf0ff2b9bb19fb2e9bbb235882ed4ec",
    "raw_adversarial": "17c77d34a7bb2e27375d8ee69ca6acc2031aed8d9b3464dff6f6042291392072",
}
require(set(CORPUS) == EXPECTED_CORPUS_KEYS, "corpus top-level keys")
require(CORPUS["schema"] == "sanctuary.catalog-v3-parity-corpus.v1", "corpus schema")
for section, expected_digest in EXPECTED_CORPUS_ROW_DIGESTS.items():
    key = "source" if section == "spdx" else "name"
    names = "\n".join(item[key] for item in CORPUS[section])
    require(hashlib.sha256(names.encode()).hexdigest() == expected_digest, f"{section} row inventory")
public_key = b64url_decode(CORPUS["test_public_key"])
require(strict_public_point(decode_point(public_key)), "strict corpus public key")
require(CATALOG["signature"].endswith("w"), "signature pad-bit fixture shape")
try:
    b64url_decode(CATALOG["signature"][:-1] + "x")
    raise VerificationFailure("non-zero base64url pad bits accepted")
except ValueError as error:
    require(str(error) == "bad_signature_encoding", "non-zero base64url pad-bit refusal")
require(b64url_encode(hashlib.sha256(public_key).digest()) == CORPUS["derived_test_signer_key_id"], "operator key id")
require(
    len(CORPUS["test_catalog_keyring"]) == 1
    and CORPUS["test_catalog_keyring"][0]["signing_key_id"] == "cat-epoch-1"
    and CORPUS["test_catalog_keyring"][0]["pubkey"] == CORPUS["test_public_key"]
    and CORPUS["test_catalog_keyring"][0]["status"] == "active",
    "test catalog keyring",
)
require(validate_keyring(CORPUS["test_catalog_keyring"]) == "accept", "independent keyring admission")
for malformed_keyring in (None, {}, "keyring", [None], [{"epoch": 1}]):
    require(validate_keyring(malformed_keyring) == "invalid_value", "malformed keyring refusal")

older_public_key = encode_point(multiply(BASE, 2))
require(older_public_key != public_key, "construct independent rotation principal")
rotated_keyring = [
    {
        **copy.deepcopy(CORPUS["test_catalog_keyring"][0]),
        "pubkey": b64url_encode(older_public_key),
        "status": "retired",
        "max_catalog_version": 1,
        "max_index_version": 1,
    },
    {
        **copy.deepcopy(CORPUS["test_catalog_keyring"][0]),
        "epoch": 2,
        "signing_key_id": "cat-epoch-2",
        "min_catalog_version": 2,
        "min_index_version": 2,
    },
]
require(validate_keyring(rotated_keyring) == "accept", "valid key rotation")
require(resolve_catalog_key(rotated_keyring, "cat-epoch-1", 1, "catalog")[0] == "accept", "retired in-range catalog key")
require(resolve_catalog_key(rotated_keyring, "cat-epoch-1", 2, "catalog")[0] == "signing_key_out_of_range", "catalog key range")
require(resolve_catalog_key(rotated_keyring, "cat-epoch-9", 1, "catalog")[0] == "unknown_signing_key", "unknown catalog epoch")
revoked_keyring = copy.deepcopy(rotated_keyring)
revoked_keyring[0]["status"] = "revoked"
require(resolve_catalog_key(revoked_keyring, "cat-epoch-1", 1, "catalog")[0] == "signing_key_revoked", "revoked catalog key")
gapped_keyring = copy.deepcopy(rotated_keyring)
gapped_keyring[1]["min_index_version"] = 3
require(validate_keyring(gapped_keyring) == "invalid_value", "index epoch gap")
index_boundary = boundary("catalog-index-body-and-envelope")
unknown_entry_epoch_body = body_for(index_boundary)
unknown_entry_epoch_body["entries"][0]["catalog_key_epoch"] = 9
require(
    validate_envelope(
        index_boundary,
        envelope_for(index_boundary, unknown_entry_epoch_body),
    ) == "bad_signature",
    "index signature precedes untrusted entry key resolution",
)

catalog_for_overlay = body_for(boundary("catalog-body-and-envelope"))
overlay_for_combination = body_for(boundary("overlay-body-and-envelope"))
binding_id = overlay_for_combination["overlay_binding_id"]
require(
    validate_envelope(
        boundary("catalog-body-and-envelope"),
        envelope_for(boundary("catalog-body-and-envelope"), catalog_for_overlay),
    ) == "accept"
    and validate_envelope(
        boundary("overlay-body-and-envelope"),
        envelope_for(boundary("overlay-body-and-envelope"), overlay_for_combination),
    ) == "accept",
    "combination inputs independently authenticate",
)
require(
    validate_catalog_overlay_combination(catalog_for_overlay, overlay_for_combination, binding_id, 0)
    == "unauthenticated_input",
    "unsigned catalog-overlay combination refusal",
)
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, overlay_for_combination, binding_id, 0, _AUTHENTICATED_COMBINATION,
    ) == "accept",
    "catalog-overlay combination",
)
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, overlay_for_combination, binding_id, overlay_for_combination["overlay_version"],
        _AUTHENTICATED_COMBINATION,
    ) == "overlay_rollback",
    "overlay rollback",
)
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, overlay_for_combination, "f" * 32, 0, _AUTHENTICATED_COMBINATION,
    )
    == "overlay_binding_mismatch",
    "overlay binding",
)
colliding_overlay = copy.deepcopy(overlay_for_combination)
colliding_overlay["entries"][0]["model_id"] = catalog_for_overlay["models"][0]["model_id"]
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, colliding_overlay, binding_id, 0, _AUTHENTICATED_COMBINATION,
    )
    == "overlay_collision",
    "overlay model-id collision",
)
identity_collision = copy.deepcopy(overlay_for_combination)
identity_collision["entries"][0]["identity"] = copy.deepcopy(catalog_for_overlay["models"][0]["identity"])
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, identity_collision, binding_id, 0, _AUTHENTICATED_COMBINATION,
    )
    == "overlay_collision",
    "overlay identity collision",
)
under_assured_overlay = copy.deepcopy(overlay_for_combination)
under_assured_overlay["entries"][0]["assurance"] = "light"
under_assured_overlay["entries"][0]["surface_authorization"] = ["sentinel-scoring"]
require(
    validate_catalog_overlay_combination(
        catalog_for_overlay, under_assured_overlay, binding_id, 0, _AUTHENTICATED_COMBINATION,
    )
    == "overlay_escalation",
    "overlay assurance floor",
)

require(valid_source_url("https://example.com/license"), "canonical public source URL")
for rejected_source_url in (
    "https://127.0.0.1/license",
    "https://127.1/license",
    "https://0x7f000001/license",
    "https://169.254.1.1/license",
    "https://xn--bcher-kva.example/license",
    "https://-bad.example/license",
    "https://bad-.example/license",
    "https://example..com/license",
    "https://example.com/%2fsecret",
    "https://example.com:443/license",
    "https://example.com:0444/license",
    "https://example.com/%FF",
):
    require(not valid_source_url(rejected_source_url), f"source URL refusal: {rejected_source_url}")
# A naive Ed25519 equation accepts this existential forgery for identity A:
# choose any canonical S and set R=[S]B, so [S]B=R+[k]A for every message.
identity_key = encode_point(IDENTITY)
forged_scalar = 1
forged_r = multiply(BASE, forged_scalar)
identity_forgery = encode_point(forged_r) + forged_scalar.to_bytes(32, "little")
require(
    multiply(BASE, forged_scalar) == add(forged_r, multiply(IDENTITY, 1)),
    "identity forgery construction",
)
require(not verify_ed25519(identity_key, identity_forgery, b"sanctuary identity forgery"), "identity forgery refusal")
# With A=B (secret scalar 1), R=identity and S=H(R,A,m) satisfy the
# verification equation. Strict verification must nevertheless reject the
# small-order R encoding required to make that construction work.
identity_r_message = b"sanctuary identity-R forgery"
base_public_key = encode_point(BASE)
identity_r = encode_point(IDENTITY)
identity_r_challenge = int.from_bytes(
    hashlib.sha512(identity_r + base_public_key + identity_r_message).digest(), "little"
) % L
identity_r_signature = identity_r + identity_r_challenge.to_bytes(32, "little")
require(
    multiply(BASE, identity_r_challenge)
    == add(IDENTITY, multiply(BASE, identity_r_challenge)),
    "identity-R construction",
)
require(
    not verify_ed25519(base_public_key, identity_r_signature, identity_r_message),
    "identity-R refusal",
)
try:
    decode_point(P.to_bytes(32, "little"))
    raise VerificationFailure("noncanonical point accepted")
except ValueError:
    pass
torsion_point = decode_point(bytes.fromhex(
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
))
torsion_bearing_key = add(BASE, torsion_point)
require(multiply(torsion_bearing_key, 8) != IDENTITY, "torsion-bearing key is not small-order")
require(not strict_public_point(torsion_bearing_key), "torsion-bearing key refusal")
realistic_catalog_json = json.dumps(CATALOG["body"], separators=(",", ":"))
require(not reject_non_integer_number_lexemes(realistic_catalog_json), "realistic catalog numeric scan")
negative_catalog_json = realistic_catalog_json.replace('"catalog_version":1', '"catalog_version":-1', 1)
require(reject_non_integer_number_lexemes(negative_catalog_json), "negative integer numeric scan")
consumed = {name: 0 for name in ("boundaries", "spdx", "contract_cases", "generated_size_cases", "raw_adversarial")}

for item in CORPUS["boundaries"]:
    consumed["boundaries"] += 1
    body = body_for(item)
    canonical = canonical_json(body)
    expected_canonical = item.get("canonical_body", CATALOG["canonical_body"])
    expected_digest = item.get("body_sha256", CATALOG["canonical_body_sha256"])
    signature = b64url_decode(item.get("signature", CATALOG["signature"]))
    require(canonical == expected_canonical, item["name"])
    require(hashlib.sha256(canonical.encode()).hexdigest() == expected_digest, item["name"])
    require(verify_ed25519(public_key, signature, (item["domain"] + "\n" + canonical).encode()), item["name"])
    if item["key_field"] == "signer_key_id":
        require(item["key_id"] == CORPUS["derived_test_signer_key_id"], item["name"])
    require(execute_case({"boundary": item["name"], "operation": "parse_envelope"}) == item["verdict"], item["name"])

for fixture in CORPUS["spdx"]:
    consumed["spdx"] += 1
    verdict, canonical = parse_spdx(fixture["source"])
    require(verdict == fixture["verdict"], fixture["source"])
    if verdict == "accept":
        require(canonical == fixture["canonical"], fixture["source"])
    else:
        require("canonical" not in fixture, fixture["source"])

for fixture in CORPUS["contract_cases"]:
    consumed["contract_cases"] += 1
    require(execute_case(fixture) == fixture["verdict"], fixture["name"])

for fixture in CORPUS["generated_size_cases"]:
    consumed["generated_size_cases"] += 1
    require(fixture["measurement"] == "catalog_domain_preimage_bytes", fixture["name"])
    body = build_catalog_cap_body(fixture["preimage_bytes"])
    require(len((body["schema"] + "\n" + canonical_json(body)).encode()) == fixture["preimage_bytes"], fixture["name"])
    require(validate_catalog(body) == fixture["verdict"], fixture["name"])

for fixture in CORPUS["raw_adversarial"]:
    consumed["raw_adversarial"] += 1
    if fixture["operation"] == "parse_spdx":
        verdict, _canonical = parse_spdx(fixture["text"])
    elif fixture["operation"] == "parse_catalog_json":
        verdict = parse_catalog_json(fixture["text"], fixture.get("max_bytes", 65_536))
    else:
        raise VerificationFailure(f"unknown raw operation: {fixture['operation']}")
    require(verdict == fixture["verdict"], fixture["name"])

require(consumed == {name: len(CORPUS[name]) for name in consumed}, "consumed row counts")
require(len({item["name"] for item in CORPUS["boundaries"]}) == len(CORPUS["boundaries"]), "unique boundaries")
require(len({item["source"] for item in CORPUS["spdx"]}) == len(CORPUS["spdx"]), "unique SPDX rows")
for section in ("contract_cases", "generated_size_cases", "raw_adversarial"):
    require(len({item["name"] for item in CORPUS[section]}) == len(CORPUS[section]), f"unique {section}")

print(
    "S1_PARITY_OK "
    + " ".join(f"{name}={consumed[name]}" for name in ("boundaries", "contract_cases", "generated_size_cases", "raw_adversarial", "spdx"))
)
