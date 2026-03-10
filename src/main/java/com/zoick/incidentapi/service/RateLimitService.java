package com.zoick.incidentapi.service;

import com.zoick.incidentapi.domain.TrustTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
/**
Rate limiting via redis fixed-window counters.
 Key schema-> rate :user{userId}-> per-user bucket, limit from trustTier.getRequestPerminute()
 rate:admin{userId}-> admin bucket, fixed 60 req/min, never trust-score-derived

 * Window: 60 seconds. Counter increments on each request. TTL set on first increment only.
 *
 * FAIL OPEN: if Redis is unavailable, the request is allowed and REDIS_UNAVAILABLE is logged.
 * Redis holds no source of truth. Its unavailability must never deny a legitimate user.
 *
 * This service does not call TrustScoreService. It only checks the counter.
 * The caller (RateLimitFilter) is responsible for penalizing on violation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitService {
    private static final int ADMIN_RATE_LIMIT= 60;
    private static final Duration WINDOW_DURATION= Duration.ofSeconds(60);
    private final RedisTemplate<String, String> redisTemplate;
    /**
     * check whether the request should be allowed
     * @param userId the authenticated user's ID
     * @param isAdmin true if the user holds ROLE_ADMIN
     * @param tier the user's current trust tier(ignored for admins)
     * @return true if thr request is within the allowed limit, false if it exceeds it limit
     */
    public boolean isAllowed(String userId, boolean isAdmin, TrustTier tier){
        String key= isAdmin ? adminKey(userId) : userKey(userId);
        int limit= isAdmin ? ADMIN_RATE_LIMIT : tier.getRequestsPerMinute();
        try{
            Long count= redisTemplate.opsForValue().increment(key);
            if (count == null) {
                //redis returned null- trear as fail-open
                log.warn("REDID_UNAVAILABLE: increment returned null for key={}", key);
                return true;
            }
            if(count == 1L){
                //first request in this window-> set the expiry
                redisTemplate.expire(key, WINDOW_DURATION);
            }
            return count <= limit;
        }catch (Exception e){
            log.warn("REDIS_UUNAVAILABLE: rate limit check failed for userId={}, key={}, error={}",
                    userId, key, e.getMessage());
            return true; //fail open- never deny becos redis is down
        }
    }
    //key builders
    private String userKey(String userId){
        return "rate:user:" + userId;
    }
    private String adminKey(String userId){
        return "rate:admin:" + userId;
    }
}
