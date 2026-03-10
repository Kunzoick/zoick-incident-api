package com.zoick.incidentapi.audit;

/**
 * Every auditable action in the system is defined here.
 * This enum is the only place where audit action names are defined. Never use raw strings for audit actions.
 * if an action is not in this enum, it can not be auditable
 */

public enum AuditEventType {
    //-Authentication
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGIN_LOCKOUT,
    LOGOUT,

    //-Token events
    TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_REVOKED,
    TOKEN_REUSE_DETECTED,

    //-incident events
    INCIDENT_SUBMITTED,
    INCIDENT_REVIEWED,
    INCIDENT_ESCALATED,
    INCIDENT_RESOLVED,
    INCIDENT_REJECTED,
    INCIDENT_CORROBORATED,
    DUPLICATE_DETECTED,

    //-TRUST score events
    TRUST_SCORE_CHANGED,
    TRUST_TIER_BLOCKED,

    // ── Abuse & Security Events
    RATE_LIMIT_HIT,
    PERMISSION_DENIED,
    ACCOUNT_LOCKED,
    ACCOUNT_UNLOCKED,

    // ── Admin Actions
    ADMIN_TRUST_OVERRIDE,
    ADMIN_ACCOUNT_LOCK,
    ADMIN_ACCOUNT_UNLOCK,
    ADMIN_INCIDENT_REVIEW,
    ADMIN_INCIDENT_ESCALATE,
    ADMIN_CORROBORATION_LINK,

    // ── System Events
    REDIS_UNAVAILABLE,
    SYSTEM_ERROR


}
