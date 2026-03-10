package com.zoick.incidentapi.service;

import com.zoick.incidentapi.audit.AuditEventType;
import com.zoick.incidentapi.domain.*;
import com.zoick.incidentapi.repository.AuditLogRepository;
import com.zoick.incidentapi.repository.TrustScoreHistoryRepository;
import com.zoick.incidentapi.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Single source of truth for all trust score mutations
 * per Iron rule-> trust score governs capacity and scrutiny, role governs structural access
 * these never mix here
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class TrustScoreService {
    private final UserRepository userRepository;
    private final TrustScoreHistoryRepository trustScoreHistoryRepository;
    private final AuditLogRepository auditLogRepository;
    // public api
    /**
     * applies a trust score delta to a user, positive delts= reward negative delta= penalty
     * clamps result history record, fires audit log
     */
    @Transactional
    public void applyDelta(User user, int delta, TrustChangeReason reason, String changedBy,
                           HttpServletRequest request){
        int previous= user.getTrustScore();
        int newScore= Math.clamp(previous + delta, 0, 100);
        user.setTrustScore(newScore);
        userRepository.save(user);

        writeTrustHistory(user.getId(), previous, newScore, reason, changedBy);
        writeAuditLog(user.getId(), changedBy, AuditEventType.TRUST_SCORE_CHANGED, TargetType.USER,
                user.getId(), request);
        log.info("Trust score changed | userId={} | {} -> {} | reason={} | correlationId={}",
                user.getId(), previous, newScore, reason, getCorrelationId(request));
    }
    /**
     * Admin override-> set trust score to exact value used by admin enpoints
     * still clamped and still writes history
     */
    @Transactional
    public void adminOverride(User user, int newScore, String adminId, HttpServletRequest request){
        int previous= user.getTrustScore();
        int clamped= Math.clamp(newScore, 0, 100);
        user.setTrustScore(clamped);
        userRepository.save(user);

        writeTrustHistory(user.getId(), previous, clamped,
                TrustChangeReason.ADMIN_OVERRIDE, adminId);

        writeAuditLog(user.getId(), adminId,
                AuditEventType.TRUST_SCORE_CHANGED,
                TargetType.USER, user.getId(), request);

        log.info("Trust score admin override | userId={} | {} → {} "
                        + "| adminId={} | correlationId={}",
                user.getId(), previous, clamped,
                adminId, getCorrelationId(request));
    }
    //token reuse detected-> apply penalty and increment tokenVersion-> per DDR-001(token reuse is treated as a compromise signal)
    //score deduction= -15
    @Transactional
    public void penalizeTokenReuse(User user, HttpServletRequest request){
        applyDelta(user, -15, TrustChangeReason.TOKEN_REUSE, "SYSTEM", request);
        userRepository.incrementTokenVersion(user.getId());
        log.warn("Token reuse penalty applied | userId={} | correlationId={}", user.getId(), getCorrelationId(request));
    }
    /**
     * rate limit hit-> apply small penalty, per DDR-003(repeated rate limit violations reduce trust)
     * score deduction= -2 per violation
     */
    @Transactional
    public void penalizeRateLimit(User user, HttpServletRequest request){
        applyDelta(user, -2, TrustChangeReason.RATE_LIMIT_HIT, "SYSTEM", request);
    }
    // report validated by admin- reward submitter
    //score reward= +10
    @Transactional
    public void rewardValidatedReport(User user, String adminId, HttpServletRequest request){
        applyDelta(user, +10, TrustChangeReason.REPORT_VALIDATED, adminId, request);
    }
    /**
     * report rejected as spam- penelaize submitter
     * score deduction= -10
     */
    @Transactional
    public void penalizeSpam(User user, String adminId, HttpServletRequest request){
        applyDelta(user, -10, TrustChangeReason.SPAM_FLAGGED, adminId, request);
    }
    /**
     * duplicate submission detected
     * score deduction= -5
     */
    @Transactional
    public void penalizeDuplicate(User user, HttpServletRequest request){
        applyDelta(user, -5, TrustChangeReason.DUPLICATE_DETECTED, "SYSTEM", request);
    }

    //internal
    private void writeTrustHistory(String userId, int previousScore, int newScore, TrustChangeReason reason, String changedBy){
        TrustScoreHistory history= TrustScoreHistory.builder().id(UUID.randomUUID().toString())
                .userId(userId).previousScore(previousScore).newScore(newScore).changeReason(reason)
                .changedBy(changedBy).build();
        trustScoreHistoryRepository.save(history);
    }
    private void writeAuditLog(String actorId, String initiatedBy, AuditEventType action, TargetType targetType,
                               String targetId, HttpServletRequest request){
        AuditLog entry= AuditLog.builder().id(UUID.randomUUID().toString()).actorId(initiatedBy)
                .action(action).targetType(targetType).targetId(targetId).ipAddress(getIpAddress(request))
                .correlationId(getCorrelationId(request)).build();
        auditLogRepository.save(entry);
    }
    private String getIpAddress(HttpServletRequest request){
        String ip= request.getHeader("X-Forwarded-For");
        return (ip != null && !ip.isEmpty()) ? ip : request.getRemoteAddr();
    }
    private String getCorrelationId(HttpServletRequest request){
        Object id= request.getAttribute("X-Correlation-Id");
        return id != null ? id.toString() : "unknown";
    }
}
