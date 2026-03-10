package com.zoick.incidentapi.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zoick.incidentapi.domain.TrustTier;
import com.zoick.incidentapi.domain.User;
import com.zoick.incidentapi.dto.response.ErrorResponse;
import com.zoick.incidentapi.repository.UserRepository;
import com.zoick.incidentapi.service.RateLimitService;
import com.zoick.incidentapi.service.TrustScoreService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * Rate limiting filter — runs after JwtFilter in the security filter chain.
 *
 * Execution order:
 *   JwtFilter        → establishes who the user is (sets SecurityContext)
 *   RateLimitFilter  → checks how many requests they are allowed (this filter)
 *   Controllers      → only reached if both pass
 *
 * Behaviour matrix:
 *   Unauthenticated request  → pass through (Spring Security rejects at security layer)
 *   BLOCKED tier (score<20)  → 403 TRUST_BLOCKED (DDR-003, no Redis touched)
 *   Within rate limit        → pass through
 *   Exceeds rate limit       → penalize trust (-2), return 429 RATE_LIMIT_EXCEEDED
 *   Redis unavailable        → fail open, log REDIS_UNAVAILABLE, pass through
 *   User not found in DB     → fail open, log warning, pass through
 *
 * The Iron Rule is preserved: BLOCKED tier is a trust-score behavioral block,
 * not a structural permission denial. It is checked here, not in the security layer.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService   rateLimitService;
    private final TrustScoreService  trustScoreService;
    private final UserRepository     userRepository;
    private final ObjectMapper       objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Unauthenticated — not our concern here. Spring Security handles it.
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            filterChain.doFilter(request, response);
            return;
        }

        // userId is stored as the principal name by JwtFilter
        String userId= auth.getName();

        // Load the user — DB read per request (Redis cache is documented evolution path)
        Optional<User> userOpt = loadUser(userId);
        if (userOpt.isEmpty()) {
            // Fail open — do not block a request because of a filter-level DB issue
            filterChain.doFilter(request, response);
            return;
        }

        User      user    = userOpt.get();
        TrustTier tier    = user.getTrustTier();
        boolean   isAdmin = auth.getAuthorities()
                .contains(new SimpleGrantedAuthority("ROLE_ADMIN"));

        // DDR-003: BLOCKED tier is a behavioral block — 403 TRUST_BLOCKED.
        // This is checked independently of account_locked (auth layer).
        // Do NOT touch Redis for a BLOCKED user — they get 0 requests per minute.
        if (!isAdmin && tier == TrustTier.BLOCKED) {
            log.info("TRUST_BLOCKED: userId={}, trustScore={}", userId, user.getTrustScore());
            writeForbidden(response, "TRUST_BLOCKED", "Your trust score is too low to make requests.");
            return;
        }

        // Check the rate limit counter in Redis
        boolean allowed = rateLimitService.isAllowed(userId, isAdmin, tier);

        if (!allowed) {
            log.info("RATE_LIMIT_EXCEEDED: userId={}, tier={}, isAdmin={}", userId, tier, isAdmin);

            // Penalize for rate limit abuse — but only for non-admin users
            if (!isAdmin) {
                try {
                    trustScoreService.penalizeRateLimit(user, request);
                } catch (Exception e) {
                    // Trust penalty failure must not block the 429 response
                    log.warn("Trust penalty failed after rate limit for userId={}: {}", userId, e.getMessage());
                }
            }

            writeTooManyRequests(response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    // ── Response writers ─────────────────────────────────────────────────────

    private void writeForbidden(HttpServletResponse response, String errorCode, String message)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(
                ErrorResponse.of(403, errorCode, message, null, null)
        ));
    }

    private void writeTooManyRequests(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(
                ErrorResponse.of(429, "RATE_LIMIT_EXCEEDED",
                        "Too many requests. Please slow down.", null, null)
        ));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Optional<User> loadUser(String userId) {
        try {
            return userRepository.findById(userId);
        } catch (Exception e) {
            log.warn("RateLimitFilter: DB error loading userId={}, failing open: {}", userId, e.getMessage());
            return Optional.empty();
        }
    }
}