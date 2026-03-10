package com.zoick.incidentapi.domain;

/**
 * incident status
 * PENDING: UNDER_REVIEW-> ESCALATED
 * PENDING: UNDER_REVIEW-> RESOLVED
 * PENDING: UNDER_REVIEW-> REJECTED
 */
public enum IncidentStatus {
    PENDING,
    UNDER_REVIEW,
    ESCALATED,
    RESOLVED,
    REJECTED;

    public boolean canTransitionTo(IncidentStatus target){
        return switch (this){
            case PENDING -> target == UNDER_REVIEW;
            case UNDER_REVIEW -> target == ESCALATED || target == RESOLVED
                    || target == REJECTED;
            case ESCALATED -> target == RESOLVED || target == REJECTED;
            case RESOLVED, REJECTED -> false;
        };
    }
}
