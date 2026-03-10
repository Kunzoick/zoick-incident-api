package com.zoick.incidentapi.service;

import com.zoick.incidentapi.audit.AuditEventType;
import com.zoick.incidentapi.domain.*;
import com.zoick.incidentapi.repository.AuditLogRepository;
import com.zoick.incidentapi.repository.IncidentRepository;
import com.zoick.incidentapi.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.UUID;


/**
 * core incident business logic(DDR-002)
 * enforces -> trust tier check before submission
 * duplicate detection per DDR-004, ownership check on every user fetch
 * state machine on status transitions(IncidentStatus)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {
    private final IncidentRepository incidentRepository;
    private final TrustScoreService trustScoreService;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
   // private final TrustScoreHistoryRepository trustScoreHistoryRepository;
    private static final int MAX_PAGE_SIZE = 100;
    private static final int DEFAULT_PAGE_SIZE = 20;
    @PersistenceContext
    private EntityManager entityManager;
    //submit
    /**
     * submits a new incident report
     * load user and check trust tier- BLOCKED= reject
     * Compute content hash for duplicate detection
     * Check for duplicate within 24-hour window per DDR-004
     * Build and save incident
     * Write audit log
     */
    @Transactional
    public Incident submit(String userId, String title, String description, Severity suggestedSeverity, HttpServletRequest request) {
        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalStateException("Authenticated user not found: " + userId));
        //trust tier check
        if (!user.canSubmit()) {
            writeAuditLog(userId, AuditEventType.TRUST_TIER_BLOCKED, TargetType.USER, userId, request);
            throw new com.zoick.incidentapi.exception.TrustBlockedException("Your trust score is too low to submit reports.");
        }
        //compute content hash
        String contentHash = hashContent(title, description);
        // Duplicate detection — same user, same content, 24h window
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        boolean isDuplicate = incidentRepository.existsDuplicate(
                userId, contentHash, since);
        if (isDuplicate) {
            writeAuditLog(
                    userId,
                    AuditEventType.DUPLICATE_DETECTED,
                    TargetType.INCIDENT,
                    null,
                    request
            );
            // Deduct trust score per DDR-004: -5 for duplicate
            trustScoreService.penalizeDuplicate(user, request);
            throw new com.zoick.incidentapi.exception
                    .DuplicateSubmissionException(
                    "You have already submitted this report "
                            + "within the last 24 hours.");
        }
        //build incident
        Incident incident= Incident.builder().id(UUID.randomUUID().toString()).userId(userId).title(title).description(description)
                .contentHash(contentHash).suggestedSeverity(suggestedSeverity).status(IncidentStatus.PENDING).credibilityScore(user.getTrustScore())
                .corroborationCount(0).submitterTrustScoreAtTime(user.getTrustScore()).build();
        log.debug("About to save incident - id={} userId={} title={}",
                incident.getId(),
                incident.getUserId(),
                incident.getTitle());
        entityManager.persist(incident);
        writeAuditLog(userId, AuditEventType.INCIDENT_SUBMITTED, TargetType.INCIDENT, incident.getId(), request);
        log.info("Incident submitted | incidentId={} | userId={} | credibility={} | correlationId={}", incident.getId(), userId,
                incident.getCredibilityScore(), getCorrelationId(request));
        return incident;
    }
    //user fetch
    /**
     * Returns a paginated list of the caller,s own incidents, ownership is implicit-> userId comes from JWT principal
     */
    @Transactional(readOnly = true)
    public Page<Incident> getOwnIncidents(String userId, int page, int pageSize){
        Pageable pageable= buildPageable(page, pageSize, Sort.by(Sort.Direction.DESC, "submittedAt"));
        return incidentRepository.findByUserIdOrderBySubmittedAtDesc(userId, pageable);
    }
    /**
     * returns a single incident-> ownership enforced, returns 403 ACCESS_DENIED if not owner
     * Never returns 404 for ownerahip violations-> per contract
     */
    @Transactional(readOnly = true)
    public Incident getOwnIncident(String incidentId, String userId){
        return incidentRepository.findByIdAndUserId(incidentId, userId).orElseThrow(() ->
                new org.springframework.security.access.AccessDeniedException("Access denied"));
    }
    // ── Admin Fetch ───────────────────────────────────────────────────────

    /**
     * Admin view — all incidents ordered by credibility
     * score descending then severity. Per DDR-005.
     */
    @Transactional(readOnly = true)
    public Page<Incident> getAllIncidents(int page, int pageSize) {
        Pageable pageable = buildPageable(page, pageSize, Sort.unsorted());
        return incidentRepository.findAllForAdminQueue(pageable);
    }

    /**
     * Admin fetch single incident — no ownership restriction.
     */
    @Transactional(readOnly = true)
    public Incident getIncidentAsAdmin(String incidentId) {
        return incidentRepository.findById(incidentId)
                .orElseThrow(() ->
                        new jakarta.persistence.EntityNotFoundException(
                                "Incident not found: " + incidentId));
    }

    // ── Admin Review ──────────────────────────────────────────────────────

    /**
     * Admin reviews an incident — sets confirmed severity and status.
     *
     * Status machine enforced — invalid transitions rejected.
     * Trust score events fired based on verdict:
     * - RESOLVED → +10 trust score
     * - REJECTED → -10 trust score (spam signal)
     */
    @Transactional
    public Incident review(
            String incidentId,
            String adminId,
            Severity confirmedSeverity,
            IncidentStatus newStatus,
            HttpServletRequest request
    ) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() ->
                        new jakarta.persistence.EntityNotFoundException(
                                "Incident not found: " + incidentId));

        // State machine check
        if (!incident.getStatus().canTransitionTo(newStatus)) {
            throw new IllegalStateException(
                    "Invalid status transition: "
                            + incident.getStatus() + " → " + newStatus);
        }

        // Apply review
        incident.setConfirmedSeverity(confirmedSeverity);
        incident.setStatus(newStatus);
        incident.setReviewedAt(LocalDateTime.now());
        incident.setReviewedBy(adminId);

        incidentRepository.save(incident);

        // Trust score events based on verdict
        User submitter = userRepository.findById(incident.getUserId())
                .orElse(null);

        if (submitter != null) {
            if (newStatus == IncidentStatus.RESOLVED) {
                trustScoreService.rewardValidatedReport(submitter, adminId, request);
            } else if (newStatus == IncidentStatus.REJECTED) {
                trustScoreService.penalizeSpam(submitter, adminId, request);
            }
        }

        writeAuditLog(
                adminId,
                AuditEventType.INCIDENT_REVIEWED,
                TargetType.INCIDENT,
                incidentId,
                request
        );

        log.info("Incident reviewed | incidentId={} | status={} "
                        + "| adminId={} | correlationId={}",
                incidentId, newStatus, adminId,
                getCorrelationId(request));

        return incident;
    }

    // ── Admin Escalate ────────────────────────────────────────────────────

    /**
     * Escalates an incident to ESCALATED status.
     * Must be in PENDING or UNDER_REVIEW to escalate.
     */
    @Transactional
    public Incident escalate(
            String incidentId,
            String adminId,
            HttpServletRequest request
    ) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() ->
                        new jakarta.persistence.EntityNotFoundException(
                                "Incident not found: " + incidentId));

        if (!incident.getStatus()
                .canTransitionTo(IncidentStatus.ESCALATED)) {
            throw new IllegalStateException(
                    "Cannot escalate incident in status: "
                            + incident.getStatus());
        }

        incident.setStatus(IncidentStatus.ESCALATED);
        incident.setReviewedAt(LocalDateTime.now());
        incident.setReviewedBy(adminId);
        incidentRepository.save(incident);

        writeAuditLog(
                adminId,
                AuditEventType.INCIDENT_ESCALATED,
                TargetType.INCIDENT,
                incidentId,
                request
        );

        log.info("Incident escalated | incidentId={} | adminId={} "
                        + "| correlationId={}",
                incidentId, adminId, getCorrelationId(request));

        return incident;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * SHA-256 hash of title + description.
     * Per DDR-004 — single place where content hash is computed.
     */
    private String hashContent(String title, String description) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");
            String combined = title + "||" + description;
            byte[] hash = digest.digest(
                    combined.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Applies a trust score delta to a user.
     * Score is always clamped 0–100.
     * Change written to trust_score_history.
     */
   /*
    private void deductTrustScore(
            User user,
            int delta,
            String reason,
            HttpServletRequest request
    ) {
        int previous = user.getTrustScore();
        int newScore = Math.clamp(previous + delta, 0, 100);
        user.setTrustScore(newScore);
        userRepository.save(user);
        //write to trust_score_history- every change is recorded
        TrustScoreHistory history= TrustScoreHistory.builder().id(java.util.UUID.randomUUID().toString())
                        .userId(user.getId()).previousScore(previous).newScore(newScore).changeReason(TrustChangeReason.valueOf(reason))
                        .build();
        trustScoreHistoryRepository.save(history);

        log.info("Trust score changed | userId={} | {} → {} "
                        + "| reason={} | correlationId={}",
                user.getId(), previous, newScore,
                reason, getCorrelationId(request));
    }
    */

    /**
     * Builds a Pageable — enforces max page size of 100.
     */
    private Pageable buildPageable(int page, int pageSize, Sort sort) {
        int size = Math.min(
                pageSize > 0 ? pageSize : DEFAULT_PAGE_SIZE,
                MAX_PAGE_SIZE);
        int pageIndex = Math.max(page - 1, 0);
        return PageRequest.of(pageIndex, size, sort);
    }

    private void writeAuditLog(
            String actorId,
            AuditEventType action,
            TargetType targetType,
            String targetId,
            HttpServletRequest request
    ) {
        AuditLog entry = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .actorId(actorId)
                .action(action)
                .targetType(targetType)
                .targetId(targetId)
                .ipAddress(getIpAddress(request))
                .correlationId(getCorrelationId(request))
                .build();
        auditLogRepository.save(entry);
    }

    private String getIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        return (ip != null && !ip.isEmpty())
                ? ip : request.getRemoteAddr();
    }

    private String getCorrelationId(HttpServletRequest request) {
        Object id = request.getAttribute("X-Correlation-Id");
        return id != null ? id.toString() : "unknown";
    }
}
