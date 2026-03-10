package com.zoick.incidentapi.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;

@Getter
public class TrustOverrideRequest {

    @NotNull
    @Min(0)
    @Max(100)
    private Integer newScore;

    @NotNull
    private String reason;
}