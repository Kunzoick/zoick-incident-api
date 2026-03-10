package com.zoick.incidentapi.domain;

/**
 * incident severity levels
 * suggested_severity: set by submitting user
 * confirmed_severity: set by admin on review
 */
public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
