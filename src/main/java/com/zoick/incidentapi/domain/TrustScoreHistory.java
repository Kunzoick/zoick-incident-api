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
@Table(name = "trust_score_history")
public class TrustScoreHistory {
    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @Column(name = "previous_score", nullable = false)
    private int previousScore;

    @Column(name = "new_score", nullable = false)
    private int newScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "change_reason", nullable = false, length = 30)
    private TrustChangeReason changeReason;

    @Column(name = "changed_by", length = 36)
    private String changedBy;

    @Column(name = "changed_at", nullable = false, updatable = false)
    private LocalDateTime changedAt;

    @PrePersist
    protected void onCreate() {
        if (this.changedAt == null) {
            this.changedAt = LocalDateTime.now();
        }
    }
}
