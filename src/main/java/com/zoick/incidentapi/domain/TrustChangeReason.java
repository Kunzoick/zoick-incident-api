package com.zoick.incidentapi.domain;

public enum TrustChangeReason {
    REPORT_VALIDATED,
    DUPLICATE_DETECTED,
    RATE_LIMIT_HIT,
    SPAM_FLAGGED,
    TOKEN_REUSE,
    DECAY,
    ADMIN_OVERRIDE,
    INACTIVITY_DECAY
}
