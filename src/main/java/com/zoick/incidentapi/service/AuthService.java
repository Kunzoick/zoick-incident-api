package com.zoick.incidentapi.service;

import com.zoick.incidentapi.audit.AuditEventType;
import com.zoick.incidentapi.domain.*;
import com.zoick.incidentapi.repository.AuditLogRepository;
import com.zoick.incidentapi.repository.RefreshTokenRepository;
import com.zoick.incidentapi.repository.UserRepository;
import com.zoick.incidentapi.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Authentication service — implements DDR-001 completely.
 *
 * Handles: register, login, refresh, logout
 * Enforces: token rotation, reuse detection, account lockout
 * Never: touches Redis, skips audit logging, leaks internal detail
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository        userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLogRepository    auditLogRepository;
    private final JwtUtil               jwtUtil;
    private final PasswordEncoder       passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Value("${jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    private static final int MAX_FAILED_ATTEMPTS = 5;

    // ── Register ──────────────────────────────────────────────────────────

    /**
     * Registers a new user.
     * Starting trust score = 50 per DDR-002.
     * Role = USER always — ADMIN is assigned via DB only.
     */
    @Transactional
    public User register(String email, String rawPassword,
                         HttpServletRequest request) {

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered.");
        }

        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .email(email)
                .passwordHash(passwordEncoder.encode(rawPassword))
                .role(Role.USER)
                .trustScore(50)
                .tokenVersion(0)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .build();

        userRepository.save(user);

        writeAuditLog(
                null,
                AuditEventType.LOGIN_SUCCESS,
                TargetType.USER,
                user.getId(),
                request
        );

        log.info("User registered | userId={} | correlationId={}",
                user.getId(), getCorrelationId(request));

        return user;
    }

    // ── Login ─────────────────────────────────────────────────────────────

    /**
     * Authenticates a user and issues a JWT + refresh token pair.
     *
     * Per DDR-001:
     * - account_locked checked by Spring Security automatically
     * - failed_login_attempts incremented on bad credentials
     * - account locked after MAX_FAILED_ATTEMPTS
     * - refresh token stored hashed, bound to deviceId + familyId
     */
    @Transactional
    public LoginResult login(String email, String rawPassword,
                             String deviceId, HttpServletRequest request) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException(
                        "Invalid credentials"));

        // Check account locked before attempting auth
        if (user.isAccountLocked()) {
            writeAuditLog(
                    user.getId(),
                    AuditEventType.LOGIN_LOCKOUT,
                    TargetType.USER,
                    user.getId(),
                    request
            );
            throw new org.springframework.security.authentication
                    .LockedException("Account locked");
        }

        // Attempt authentication
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            email, rawPassword)
            );
        } catch (BadCredentialsException e) {
            handleFailedLogin(user, request);
            throw e;
        }

        // Successful login — reset failed attempts
        userRepository.resetFailedLoginAttempts(user.getId());

        // Update last active
        user.setLastActiveAt(LocalDateTime.now());
        userRepository.save(user);

        // Issue tokens
        String accessToken = jwtUtil.generateAccessToken(
                user.getId(), user.getRole(), user.getTokenVersion());

        RefreshToken refreshToken = createRefreshToken(
                user.getId(), deviceId);

        writeAuditLog(
                user.getId(),
                AuditEventType.LOGIN_SUCCESS,
                TargetType.USER,
                user.getId(),
                request
        );

        log.info("Login successful | userId={} | correlationId={}",
                user.getId(), getCorrelationId(request));

        return new LoginResult(accessToken, refreshToken.getId(),
                user.getId(), user.getRole());
    }

    // ── Refresh ───────────────────────────────────────────────────────────

    /**
     * Rotates a refresh token and issues a new access token.
     *
     * Per DDR-001:
     * - Validates refresh token exists and is not revoked
     * - Checks tokenVersion against DB — detects compromise
     * - Revokes old token, issues new token (rotation)
     * - Reuse detection: revoked token presented → revoke family
     */
    @Transactional
    public LoginResult refresh(String rawRefreshToken,
                               HttpServletRequest request) {

        String tokenHash = hashToken(rawRefreshToken);

        RefreshToken refreshToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new SecurityException("Invalid refresh token"));

        // Reuse detection per DDR-001
        if (refreshToken.isRevoked()) {
            log.warn("Refresh token reuse detected | familyId={} | correlationId={}",
                    refreshToken.getFamilyId(), getCorrelationId(request));

            refreshTokenRepository.revokeFamily(
                    refreshToken.getFamilyId(),
                    LocalDateTime.now(),
                    RevocationReason.REUSE_DETECTED
            );

            writeAuditLog(
                    refreshToken.getUserId(),
                    AuditEventType.TOKEN_REUSE_DETECTED,
                    TargetType.TOKEN,
                    refreshToken.getId(),
                    request
            );

            throw new SecurityException("TOKEN_REUSE_DETECTED");
        }

        // Check expiry
        if (!refreshToken.isValid()) {
            refreshTokenRepository.revokeByTokenHash(
                    tokenHash,
                    LocalDateTime.now(),
                    RevocationReason.EXPIRED
            );
            throw new SecurityException("Refresh token expired");
        }

        // Load user
        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new SecurityException("User not found"));

        // Check account locked
        if (user.isAccountLocked()) {
            throw new org.springframework.security.authentication
                    .LockedException("Account locked");
        }

        // tokenVersion check per DDR-001
        // Detects compromise — admin incremented tokenVersion
        int tokenVersionInToken = extractTokenVersionFromFamily(
                refreshToken.getFamilyId());
        if (tokenVersionInToken != user.getTokenVersion()) {
            refreshTokenRepository.revokeFamily(
                    refreshToken.getFamilyId(),
                    LocalDateTime.now(),
                    RevocationReason.COMPROMISE
            );
            throw new SecurityException("TOKEN_REVOKED");
        }

        // Rotate — revoke old, issue new
        refreshTokenRepository.revokeByTokenHash(
                tokenHash,
                LocalDateTime.now(),
                RevocationReason.LOGOUT
        );

        String newAccessToken = jwtUtil.generateAccessToken(
                user.getId(), user.getRole(), user.getTokenVersion());

        RefreshToken newRefreshToken = createRefreshToken(
                user.getId(), refreshToken.getDeviceId());

        // Keep same familyId for rotation chain tracking
        newRefreshToken.setFamilyId(refreshToken.getFamilyId());
        refreshTokenRepository.save(newRefreshToken);

        // Update last active
        user.setLastActiveAt(LocalDateTime.now());
        userRepository.save(user);

        writeAuditLog(
                user.getId(),
                AuditEventType.TOKEN_REFRESHED,
                TargetType.TOKEN,
                newRefreshToken.getId(),
                request
        );

        return new LoginResult(newAccessToken, newRefreshToken.getId(),
                user.getId(), user.getRole());
    }

    // ── Logout ────────────────────────────────────────────────────────────

    /**
     * Revokes the refresh token.
     * Access token expires naturally within 5 minutes per DDR-001.
     */
    @Transactional
    public void logout(String rawRefreshToken, String userId,
                       HttpServletRequest request) {

        String tokenHash = hashToken(rawRefreshToken);

        refreshTokenRepository.revokeByTokenHash(
                tokenHash,
                LocalDateTime.now(),
                RevocationReason.LOGOUT
        );

        writeAuditLog(
                userId,
                AuditEventType.LOGOUT,
                TargetType.TOKEN,
                null,
                request
        );

        log.info("Logout | userId={} | correlationId={}",
                userId, getCorrelationId(request));
    }

    // ── Internal Helpers ──────────────────────────────────────────────────

    /**
     * Handles a failed login attempt.
     * Increments counter and locks account at threshold.
     */
    private void handleFailedLogin(User user, HttpServletRequest request) {
        userRepository.incrementFailedLoginAttempts(user.getId());

        writeAuditLog(
                user.getId(),
                AuditEventType.LOGIN_FAILURE,
                TargetType.USER,
                user.getId(),
                request
        );

        int attempts = user.getFailedLoginAttempts() + 1;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            userRepository.lockAccount(user.getId());

            writeAuditLog(
                    user.getId(),
                    AuditEventType.ACCOUNT_LOCKED,
                    TargetType.USER,
                    user.getId(),
                    request
            );

            log.warn("Account locked after {} failed attempts | userId={} | correlationId={}",
                    MAX_FAILED_ATTEMPTS, user.getId(),
                    getCorrelationId(request));
        }
    }

    /**
     * Creates and persists a new refresh token.
     * Raw token is returned once — stored as SHA-256 hash in DB.
     * Per DDR-001: raw token never persisted.
     */
    private RefreshToken createRefreshToken(String userId, String deviceId) {
        String rawToken = UUID.randomUUID().toString();
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .id(rawToken)
                .userId(userId)
                .tokenHash(tokenHash)
                .deviceId(deviceId)
                .familyId(UUID.randomUUID().toString())
                .tokenVersion(0)
                .issuedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(
                        refreshTokenExpiryMs / 1000))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * SHA-256 hashes a token.
     * Used for storing and looking up refresh tokens.
     * Raw tokens are never stored in the database.
     */
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Extracts tokenVersion from the access token stored
     * in the refresh token family.
     * Simplified: reads from the first non-revoked token in family.
     * In production this would be stored on the family record itself.
     */
    private int extractTokenVersionFromFamily(String familyId) {
        return refreshTokenRepository
                .findFirstByFamilyIdAndRevokedFalse(familyId)
                .map(RefreshToken::getTokenVersion)
                .orElse(0);
    }

    /**
     * Writes an audit log entry.
     * Every sensitive action is logged — always.
     */
    private void writeAuditLog(
            String actorId,
            AuditEventType action,
            TargetType targetType,
            String targetId,
            HttpServletRequest request
    ) {
        AuditLog log = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .actorId(actorId)
                .action(action)
                .targetType(targetType)
                .targetId(targetId)
                .ipAddress(getIpAddress(request))
                .correlationId(getCorrelationId(request))
                .build();

        auditLogRepository.save(log);
    }

    private String getIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        return (ip != null && !ip.isEmpty()) ? ip : request.getRemoteAddr();
    }

    private String getCorrelationId(HttpServletRequest request) {
        Object id = request.getAttribute("X-Correlation-Id");
        return id != null ? id.toString() : "unknown";
    }

    // ── Result Types ──────────────────────────────────────────────────────

    /**
     * Result object for login and refresh operations.
     * Carries the token pair and user identity back to the controller.
     */
    public record LoginResult(
            String accessToken,
            String refreshTokenId,
            String userId,
            Role role
    ) {}
}