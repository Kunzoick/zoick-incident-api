package com.zoick.incidentapi.domain;

/**
 * The single source of truth for trust tiers thresholds.
 * this enum is the only place in the entire system where tier threshold are defined.
 *
 * Trust affects: CAPACITY . SCRUTINY . PRIORITY
 */
public enum TrustTier {
    TRUSTED(80, 20),
    STANDARD(50, 10),
    RESTRICTED(20, 3),
    BLOCKED(0, 0);

    private final int minimunScore;
    private final int requestsPerMinute;

    TrustTier(int minimunScore, int requestsPerMinute){
        this.minimunScore= minimunScore;
        this.requestsPerMinute= requestsPerMinute;
    }
    /**
     * the only method that resolves a score to a tier.
     * call this and never write if/else threshold logic anywhere else.
     * @param score the user's current trust score(0-100)
     * @return the corresponding trusttier
     */
    public static TrustTier fromScore(int score) {
        if(score >= TRUSTED.minimunScore) return TRUSTED;
        if(score >= STANDARD.minimunScore) return STANDARD;
        if(score >= RESTRICTED.minimunScore) return RESTRICTED;
        return BLOCKED;
    }
    public int getRequestsPerMinute(){
        return requestsPerMinute;
    }
    public int getMinimunScore(){
        return minimunScore;
    }
    public boolean canSubmit(){
        return this != BLOCKED;
    }
    public int getCorroborationWeight(){
        return switch (this) {
            case TRUSTED -> 15;
            case STANDARD -> 10;
            case RESTRICTED -> 3;
            case BLOCKED -> 0;
        };
    }
}
