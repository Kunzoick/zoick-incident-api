package com.zoick.incidentapi.repository;

import com.zoick.incidentapi.domain.Incident;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface IncidentRepository extends JpaRepository<Incident, String>{
    //ownership-aware fetch- servuce layer uses this for user requests
    Optional<Incident> findByIdAndUserId(String id, String userId);
    //user's own incidents- paginated
    Page<Incident> findByUserIdOrderBySubmittedAtDesc(String userId, Pageable pageable);// Admin queue — ordered by credibility descending then severity
    @Query("""
            SELECT i FROM Incident i
            ORDER BY i.credibilityScore DESC,
                     CASE i.suggestedSeverity
                         WHEN 'CRITICAL' THEN 1
                         WHEN 'HIGH'     THEN 2
                         WHEN 'MEDIUM'   THEN 3
                         WHEN 'LOW'      THEN 4
                     END ASC
            """)
    Page<Incident> findAllForAdminQueue(Pageable pageable);

    // Duplicate detection query — per DDR-004
    @Query("""
            SELECT COUNT(i) > 0 FROM Incident i
            WHERE i.userId = :userId
            AND i.contentHash = :contentHash
            AND i.submittedAt > :since
            """)
    boolean existsDuplicate(
            @Param("userId") String userId,
            @Param("contentHash") String contentHash,
            @Param("since") LocalDateTime since
    );

}
