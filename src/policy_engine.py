import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt injection detection patterns
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|constraints?)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|training)",
    r"you\s+are\s+now\s+(a\s+)?(?!an?\s+AI|an?\s+assistant)([\w\s]+)",
    r"new\s+(system\s+)?prompt\s*[:=]",
    r"<\s*system\s*>",
    r"\[INST\]",
    r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!an?\s+AI|an?\s+assistant)([\w\s]+)",
    r"pretend\s+(you\s+are|to\s+be)\s+(?!an?\s+AI|an?\s+assistant)([\w\s]+)",
    r"jailbreak",
    r"DAN\s*(mode)?",
    r"bypass\s+(your\s+)?(safety|security|content|ethical)\s+(filter|check|guard|restriction)",
    r"override\s+(your\s+)?(safety|security|content|ethical)\s+(setting|filter|policy)",
]

# ---------------------------------------------------------------------------
# Secret / credential exfiltration patterns
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    r"\b(password|passwd|pwd)\s*[:=]\s*\S+",
    r"\b(api[_-]?key|apikey)\s*[:=]\s*\S+",
    r"\b(secret[_-]?key|secretkey)\s*[:=]\s*\S+",
    r"\b(access[_-]?token|accesstoken)\s*[:=]\s*\S+",
    r"\b(private[_-]?key)\s*[:=]\s*\S+",
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
    r"\b[A-Za-z0-9+/]{40,}={0,2}\b",  # Base64-encoded blobs
    r"sk-[A-Za-z0-9]{32,}",            # OpenAI-style API keys
    r"AKIA[0-9A-Z]{16}",               # AWS Access Key ID
    r"ghp_[A-Za-z0-9]{36}",            # GitHub personal access token
]

# ---------------------------------------------------------------------------
# PII patterns — applied to BOTH input (redact before LLM) and output
# Each entry: (regex_pattern, replacement_token)
# ---------------------------------------------------------------------------
PII_PATTERNS = [
    # Identity
    (r"\b\d{3}-\d{2}-\d{4}\b",
     "[SSN-REDACTED]"),                                                        # US SSN
    (r"\b[A-Z]{1,2}\d{6,9}\b",
     "[PASSPORT-REDACTED]"),                                                   # Passport number
    (r"\b[A-Z]{1,2}\d{1,2}[-\s]?\d{4,6}[-\s]?[A-Z]{1,2}\b",
     "[DRIVERLICENSE-REDACTED]"),                                              # Driver's licence

    # Financial
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
     r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
     r"|(?:2131|1800|35\d{3})\d{11})\b",
     "[CARD-REDACTED]"),                                                       # Major card BINs
    (r"\b\d{16}\b",
     "[CARD-REDACTED]"),                                                       # Fallback 16-digit
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b",
     "[IBAN-REDACTED]"),                                                       # IBAN
    (r"\b\d{9,18}\b(?=.*\b(account|acct|routing|sort\s*code)\b)",
     "[BANKACCOUNT-REDACTED]"),                                                # Bank account near keyword

    # Contact
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "[EMAIL-REDACTED]"),                                                      # Email
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
     "[PHONE-REDACTED]"),                                                      # US phone
    (r"\b(?:\+44[-.\s]?)?(?:\(?0\d{4}\)?[-.\s]?\d{6}|\(?0\d{3}\)?[-.\s]?\d{7,8})\b",
     "[PHONE-REDACTED]"),                                                      # UK phone

    # Medical
    (r"\b\d{3}-\d{2}-\d{4}-\d{1}\b",
     "[MRN-REDACTED]"),                                                        # Medical record number
    (r"\b\d{3}\s?\d{3}\s?\d{4}\b(?=.*\b(nhs|national\s+health)\b)",
     "[NHS-REDACTED]"),                                                        # UK NHS number near keyword

    # Network / technical PII
    (r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
     r"\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
     "[IPV4-REDACTED]"),                                                       # IPv4
    (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
     "[IPV6-REDACTED]"),                                                       # IPv6

    # Date of birth (common formats near dob/born keywords)
    (r"(?i)(?:dob|date\s+of\s+birth|born(?:\s+on)?)\s*[:\-]?\s*"
     r"(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{2}[\/\-]\d{2})",
     "[DOB-REDACTED]"),
]

# Pre-compiled patterns for performance
COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
COMPILED_SECRETS   = [re.compile(p, re.IGNORECASE) for p in SECRET_PATTERNS]
COMPILED_PII       = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in PII_PATTERNS]

MAX_INPUT_LENGTH = 32_768


@dataclass
class PolicyResult:
    """Result object returned by all policy check functions."""

    allowed: bool
    reason: Optional[str] = None
    violations: list = field(default_factory=list)
    sanitized_text: Optional[str] = None
    pii_detections: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_prompt_injection(text: str) -> PolicyResult:
    """Scan *text* for known prompt-injection patterns. Blocks on match."""
    violations = []
    for pattern in COMPILED_INJECTION:
        if pattern.search(text):
            violations.append(f"Prompt injection detected: {pattern.pattern[:60]}")
    if violations:
        logger.warning("Prompt injection attempt detected (%d pattern(s) matched)", len(violations))
        return PolicyResult(
            allowed=False,
            reason="Prompt injection attempt blocked",
            violations=violations,
        )
    return PolicyResult(allowed=True)


def check_secret_exfiltration(text: str) -> PolicyResult:
    """Scan *text* for credential / secret patterns. Blocks on match."""
    violations = []
    for pattern in COMPILED_SECRETS:
        if pattern.search(text):
            violations.append(f"Potential secret exfiltration: {pattern.pattern[:60]}")
    if violations:
        logger.warning("Secret exfiltration attempt detected (%d pattern(s) matched)", len(violations))
        return PolicyResult(
            allowed=False,
            reason="Secret exfiltration attempt blocked",
            violations=violations,
        )
    return PolicyResult(allowed=True)


def redact_pii(text: str) -> tuple[str, list]:
    """
    Redact all PII tokens in *text* and return (sanitized_text, detections).

    Applied to both inputs (before the LLM sees them) and outputs (before
    delivery to the caller).  Returns the list of PII types that were found
    so they can be surfaced in audit logs and policy notes.
    """
    result = text
    detections = []
    for pattern, replacement in COMPILED_PII:
        if pattern.search(result):
            detections.append(replacement)
            result = pattern.sub(replacement, result)
    return result, detections


def validate_input(text: str) -> PolicyResult:
    """
    Full input validation pipeline:
    1. Prompt injection check  → block
    2. Secret exfiltration check → block
    3. Maximum length enforcement → block
    4. PII redaction → redact in-place, pass sanitized text to LLM

    Returns a PolicyResult with ``sanitized_text`` containing the PII-redacted
    version of the input that should be forwarded to the LLM backend.
    """
    injection_result = check_prompt_injection(text)
    if not injection_result.allowed:
        return injection_result

    secret_result = check_secret_exfiltration(text)
    if not secret_result.allowed:
        return secret_result

    if len(text) > MAX_INPUT_LENGTH:
        return PolicyResult(
            allowed=False,
            reason=f"Input exceeds maximum length of {MAX_INPUT_LENGTH} characters",
        )

    sanitized, pii_detections = redact_pii(text)
    if pii_detections:
        logger.info("PII redacted from input before LLM call: %s", pii_detections)

    return PolicyResult(
        allowed=True,
        sanitized_text=sanitized,
        pii_detections=pii_detections,
        reason="Input PII redacted" if pii_detections else None,
    )


def validate_output(text: str) -> PolicyResult:
    """
    Output validation pipeline:
    1. Secret exfiltration check (auto-sanitize rather than block)
    2. PII redaction

    Outputs are never hard-blocked — secrets and PII are redacted so the
    caller still receives a useful (but safe) response.
    """
    secret_result = check_secret_exfiltration(text)
    sanitized, pii_detections = redact_pii(text)

    violations = list(secret_result.violations)
    if secret_result.violations:
        logger.warning("Secrets detected in LLM output — redacting before delivery.")

    if pii_detections:
        logger.info("PII redacted from LLM output: %s", pii_detections)

    reason_parts = []
    if secret_result.violations:
        reason_parts.append("secrets redacted")
    if pii_detections:
        reason_parts.append("PII redacted")

    return PolicyResult(
        allowed=True,
        reason="Output sanitized: " + ", ".join(reason_parts) if reason_parts else None,
        sanitized_text=sanitized,
        violations=violations,
        pii_detections=pii_detections,
    )
