package com.zoick.incidentapi.domain;

import com.zoick.incidentapi.audit.AuditEventType;
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
@Table(name = "audit_logs")
public class AuditLog {
    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;
    @Column(name = "actor_id", length = 36)
    private String actorId;
    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 50)
    private AuditEventType action;
    @Enumerated(EnumType.STRING)
    @Column(name = "target_type", length = 10)
    private TargetType targetType;
    @Column(name = "target_id", length = 36)
    private String targetId;
    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;
    @Column(name = "correlation_id", nullable = false, length = 36)
    private String correlationId;
    @Column(name = "metadata", columnDefinition = "JSON")
    private String metadata;
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) this.createdAt = LocalDateTime.now();
    }
}
