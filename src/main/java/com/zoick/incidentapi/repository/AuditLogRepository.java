package com.zoick.incidentapi.repository;

import com.zoick.incidentapi.audit.AuditEventType;
import com.zoick.incidentapi.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String>{
    // Admin view — all logs paginated
    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);
    // Filter by actor
    Page<AuditLog> findByActorIdOrderByCreatedAtDesc(
            String actorId, Pageable pageable);
    // Filter by action type
    Page<AuditLog> findByActionOrderByCreatedAtDesc(
            AuditEventType action, Pageable pageable);
    // Trace a full request by correlation ID
    Page<AuditLog> findByCorrelationIdOrderByCreatedAtDesc(
            String correlationId, Pageable pageable);
}
