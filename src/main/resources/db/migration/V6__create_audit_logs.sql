CREATE TABLE audit_logs (
    id              VARCHAR(36)     NOT NULL,
    actor_id        VARCHAR(36)     NULL,
    action          ENUM(
                        'LOGIN_SUCCESS','LOGIN_FAILURE','LOGIN_LOCKOUT','LOGOUT',
                        'TOKEN_ISSUED','TOKEN_REFRESHED','TOKEN_REVOKED',
                        'TOKEN_REUSE_DETECTED',
                        'INCIDENT_SUBMITTED','INCIDENT_VIEWED','INCIDENT_REVIEWED',
                        'INCIDENT_ESCALATED','INCIDENT_RESOLVED','INCIDENT_REJECTED',
                        'INCIDENT_CORROBORATED','DUPLICATE_DETECTED',
                        'TRUST_SCORE_CHANGED','TRUST_TIER_BLOCKED',
                        'RATE_LIMIT_HIT','PERMISSION_DENIED',
                        'ACCOUNT_LOCKED','ACCOUNT_UNLOCKED',
                        'ADMIN_TRUST_OVERRIDE','ADMIN_ACCOUNT_LOCK',
                        'ADMIN_ACCOUNT_UNLOCK','ADMIN_INCIDENT_REVIEW',
                        'ADMIN_INCIDENT_ESCALATE','ADMIN_CORROBORATION_LINK',
                        'REDIS_UNAVAILABLE','SYSTEM_ERROR'
                    ) NOT NULL,
    target_type     ENUM('USER','INCIDENT','TOKEN','SYSTEM') NULL,
    target_id       VARCHAR(36)     NULL,
    ip_address      VARCHAR(45)     NOT NULL,
    correlation_id  VARCHAR(36)     NOT NULL,
    metadata        JSON            NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_audit_logs PRIMARY KEY (id),
    CONSTRAINT fk_audit_logs_actor
        FOREIGN KEY (actor_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_correlation_id ON audit_logs(correlation_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);


