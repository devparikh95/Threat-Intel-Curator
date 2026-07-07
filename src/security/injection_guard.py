import re

SUSPICIOUS_PATTERNS = [
    r"(?i)ignore\s+(?:the\s+|my\s+|any\s+|all\s+)?(?:previous|above)\s+instructions?",
    r"(?i)system\s*:\s*active",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)new\s+instructions?",
    r"(?i)override\s+system",
    r"(?i)ignore\s+all\s+rules",
    r"(?i)assistant\s*:\s*active",
]

def scan_text(text: str) -> tuple[bool, str | None]:
    """
    Scans a block of text for potential prompt injection patterns.
    
    Args:
        text: The raw, untrusted text block to scan.
        
    Returns:
        A tuple of (is_injected, reason).
    """
    if not text:
        return False, None
        
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text):
            return True, f"Matched suspicious pattern: '{pattern}'"
            
    return False, None
