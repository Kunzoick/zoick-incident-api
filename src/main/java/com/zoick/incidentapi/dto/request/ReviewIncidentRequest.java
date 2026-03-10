package com.zoick.incidentapi.dto.request;

import com.zoick.incidentapi.domain.IncidentStatus;
import com.zoick.incidentapi.domain.Severity;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
@Getter
public class ReviewIncidentRequest {
    @NotNull(message = "Confirmed severity required")
    private Severity confirmedSeverity;
    @NotNull(message = "Status is required")
    private IncidentStatus status;
}
