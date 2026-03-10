CREATE TABLE incident_corroborations (
    id                          VARCHAR(36)     NOT NULL,
    incident_id                 VARCHAR(36)     NOT NULL,
    corroborating_incident_id   VARCHAR(36)     NOT NULL,
    linked_by                   VARCHAR(36)     NOT NULL,
    corroborator_trust_score    INT             NOT NULL,
    weight_applied              INT             NOT NULL,
    linked_at                   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_incident_corroborations PRIMARY KEY (id),
    CONSTRAINT fk_corroboration_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_corroboration_source
        FOREIGN KEY (corroborating_incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_corroboration_linked_by
        FOREIGN KEY (linked_by) REFERENCES users(id),
    CONSTRAINT uq_corroboration
        UNIQUE (incident_id, corroborating_incident_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_corroborations_incident_id
    ON incident_corroborations(incident_id);