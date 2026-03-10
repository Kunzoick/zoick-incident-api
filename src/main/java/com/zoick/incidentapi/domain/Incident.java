package com.zoick.incidentapi.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "incidents")
public class Incident{

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "description", nullable = false,
            columnDefinition = "TEXT")
    private String description;

    @Column(name = "content_hash", nullable = false, length = 64)
    private String contentHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "suggested_severity", nullable = false, length = 10)
    private Severity suggestedSeverity;

    @Enumerated(EnumType.STRING)
    @Column(name = "confirmed_severity", length = 10)
    private Severity confirmedSeverity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 15)
    private IncidentStatus status;

    @Column(name = "credibility_score", nullable = false)
    private int credibilityScore;

    @Column(name = "corroboration_count", nullable = false)
    private int corroborationCount;

    @Column(name = "submitter_trust_score_at_time", nullable = false)
    private int submitterTrustScoreAtTime;

    @Column(name = "submitted_at", nullable = false)
    private LocalDateTime submittedAt;

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @Column(name = "reviewed_by", length = 36)
    private String reviewedBy;

    @Column(name = "duplicate_of", length = 36)
    private String duplicateOf;


    @PrePersist
    protected void onCreate() {
        if (this.submittedAt == null) {
            this.submittedAt = LocalDateTime.now();
        }
        if (this.status == null) {
            this.status = IncidentStatus.PENDING;
        }
        if (this.credibilityScore == 0) {
            this.credibilityScore = submitterTrustScoreAtTime;
        }
    }
}