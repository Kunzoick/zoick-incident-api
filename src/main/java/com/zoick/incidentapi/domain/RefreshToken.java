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
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @Column(name =  "id", length = 36, nullable = false, updatable = false)
    private String id;
    @Column(name = "user_id", length = 36, nullable = false, updatable = false)
    private String userId;
    @Column(name =  "token_hash", length = 64, nullable = false, unique = true)
    private String tokenHash;
    @Column(name =  "device_id", length = 255, nullable = false, updatable = false)
    private String deviceId;
    @Column(name = "family_id", length = 36, nullable = false, updatable = false)
    private String familyId;
    @Column(name = "issued_at", nullable = false, updatable = false)
    private LocalDateTime issuedAt;
    @Column(name = "expires_at", nullable = false, updatable = false)
    private LocalDateTime expiresAt;
    @Column(name = "revoked", nullable = false)
    private boolean revoked;
    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;
    @Enumerated(EnumType.STRING)
    @Column(name = "revoked_reason", length = 20)
    private RevocationReason revokedReason;
    @Column(name = "token_version", nullable = false)
    private int tokenVersion;

    public boolean isValid(){
        return !revoked && LocalDateTime.now().isBefore(expiresAt);
    }
    public void revoke(RevocationReason reason){
        this.revoked= true;
        this.revokedAt= LocalDateTime.now();
        this.revokedReason= reason;
    }

}
