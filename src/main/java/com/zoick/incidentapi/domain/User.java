package com.zoick.incidentapi.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Builder;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {
    @Id
    @Column(name= "id", length= 36, nullable= false, updatable= false)
    private String id;
    @Column(name= "email", nullable= false, unique= true, length= 255)
    private String email;
    @Column(name= "password_hash", nullable= false, length= 255)
    private String passwordHash;
    @Enumerated(EnumType.STRING)
    @Column(name= "role", nullable= false, length= 10)
    private Role role;
    @Column(name= "trust_score", nullable= false)
    private int trustScore;
    @Column(name= "token_version", nullable= false)
    private int tokenVersion;
    @Column(name= "account_locked", nullable= false)
    private boolean accountLocked;
    @Column(name= "failed_login_attempts", nullable= false)
    private int failedLoginAttempts;
    @Column(name= "last_active_at")
    private LocalDateTime lastActiveAt;
    @Column(name= "created_at", nullable= false, updatable= false)
    private LocalDateTime createdAt;
    @Column(name= "updated_at", nullable= false)
    private LocalDateTime updatedAt;
    @Version
    @Column(name = "version")
    private Long version;

    /**
     * resolves the current trust tier from this user's score. never call trusttier.fromscore() directly with a raw number
     */
    public TrustTier getTrustTier(){
        return TrustTier.fromScore(this.trustScore);
    }
    /**
     * whether this user can submit incidents
     * checks trust tier only
     */
    public boolean canSubmit(){
        return !accountLocked && getTrustTier().canSubmit();
    }
    @PrePersist
    protected void onCreate(){
        if(this.createdAt == null) this.createdAt= LocalDateTime.now();
        if(this.updatedAt == null) this.updatedAt= LocalDateTime.now();
    }
    @PreUpdate
    protected void onUpdate(){
        this.updatedAt= LocalDateTime.now();
    }
}
