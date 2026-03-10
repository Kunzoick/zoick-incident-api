CREATE TABLE trust_score_history (
    id              VARCHAR(36)     NOT NULL,
    user_id         VARCHAR(36)     NOT NULL,
    previous_score  INT             NOT NULL,
    new_score       INT             NOT NULL,
    change_reason   ENUM(
                        'REPORT_VALIDATED',
                        'DUPLICATE_DETECTED',
                        'RATE_LIMIT_HIT',
                        'SPAM_FLAGGED',
                        'TOKEN_REUSE',
                        'DECAY',
                        'ADMIN_OVERRIDE',
                        'INACTIVITY_DECAY'
                    ) NOT NULL,
    changed_by      VARCHAR(36)     NULL,
    changed_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_trust_score_history PRIMARY KEY (id),
    CONSTRAINT fk_trust_history_user
        FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_trust_history_changed_by
        FOREIGN KEY (changed_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_trust_history_user_id ON trust_score_history(user_id);
CREATE INDEX idx_trust_history_changed_at ON trust_score_history(changed_at);