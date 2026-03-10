CREATE TABLE incidents (
 id VARCHAR(36) NOT NULL,
 user_id VARCHAR(36) NOT NULL,
 title VARCHAR(255) NOT NULL,
 description TEXT NOT NULL,
 content_hash VARCHAR(64) NOT NULL,
 suggested_severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
 confirmed_severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NULL,
 status ENUM('PENDING', 'UNDER_REVIEW', 'ESCALATED', 'RESOLVED', 'REJECTED') NOT NULL DEFAULT 'PENDING',
 credibility_score INT NOT NULL DEFAULT 0,
 corroboration_count INT NOT NULL DEFAULT 0,
 submitter_trust_score_at_time INT NOT NULL,
 submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at DATETIME NULL,
 reviewed_by VARCHAR(36) NULL,
 duplicate_of VARCHAR(36) NULL,

 CONSTRAINT pk_incidents PRIMARY KEY (id),
 CONSTRAINT fk_incidents_user FOREIGN KEY (user_id) REFERENCES users(id),
 CONSTRAINT fk_incidents_reviewed_by FOREIGN KEY (reviewed_by) REFERENCES users(id),
 CONSTRAINT fk_incidents_duplicate_of FOREIGN KEY (duplicate_of) REFERENCES incidents(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_incidents_user_id ON incidents(user_id);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_submitted_at ON incidents(submitted_at);
CREATE INDEX idx_incidents_credibility ON incidents(credibility_score DESC);
CREATE INDEX idx_incidents_duplicate_check
    ON incidents(user_id, content_hash, submitted_at);