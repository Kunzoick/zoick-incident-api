package com.zoick.incidentapi.repository;

import com.zoick.incidentapi.domain.RefreshToken;
import com.zoick.incidentapi.domain.RevocationReason;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String>{
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // Reuse detection — revoke entire family per DDR-001
    @Modifying
    @Query("""
            UPDATE RefreshToken r
            SET r.revoked = true,
                r.revokedAt = :now,
                r.revokedReason = :reason
            WHERE r.familyId = :familyId
            AND r.revoked = false
            """)
    void revokeFamily(
            @Param("familyId") String familyId,
            @Param("now") LocalDateTime now,
            @Param("reason") RevocationReason reason
    );

    // Logout — revoke single token
    @Modifying
    @Query("""
            UPDATE RefreshToken r
            SET r.revoked = true,
                r.revokedAt = :now,
                r.revokedReason = :reason
            WHERE r.tokenHash = :tokenHash
            """)
    void revokeByTokenHash(
            @Param("tokenHash") String tokenHash,
            @Param("now") LocalDateTime now,
            @Param("reason") RevocationReason reason
    );

    // Cleanup expired tokens — called periodically
    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    Optional<RefreshToken> findFirstByFamilyIdAndRevokedFalse(String familyId);
}
