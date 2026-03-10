CREATE TABLE refresh_tokens (
    id              VARCHAR(36)     NOT NULL,
    user_id         VARCHAR(36)     NOT NULL,
    token_hash      VARCHAR(64)     NOT NULL,
    device_id       VARCHAR(255)    NOT NULL,
    family_id       VARCHAR(36)     NOT NULL,
    token_version   INT             NOT NULL DEFAULT 0,
    issued_at       DATETIME        NOT NULL,
    expires_at      DATETIME        NOT NULL,
    revoked         BOOLEAN         NOT NULL DEFAULT FALSE,
    revoked_at      DATETIME        NULL,
    revoked_reason  ENUM('LOGOUT','REUSE_DETECTED','COMPROMISE','EXPIRED')
                    NULL,


    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT fk_refresh_tokens_user
        FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT uq_token_hash UNIQUE (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);