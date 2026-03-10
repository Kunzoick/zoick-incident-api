package com.zoick.incidentapi.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zoick.incidentapi.domain.Incident;
import com.zoick.incidentapi.domain.IncidentStatus;
import com.zoick.incidentapi.domain.Severity;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * public representation of an incident
 * never includes sensitive information
 */
@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IncidentResponse {
    private String id;
    private String userId;
    private String title;
    private String description;
    private Severity suggestedSeverity;
    private Severity confirmedSeverity;
    private IncidentStatus status;
    private int credibilityScore;
    private int corroborationCount;
    private LocalDateTime submittedAt;
    private LocalDateTime reviewedAt;
    private String duplicateOf;
    //maps a domain incident to its response shape, single place where this mapping happens
    public static IncidentResponse from(Incident incident){
        return IncidentResponse.builder()
                .id(incident.getId())
                .userId(incident.getUserId())
                .title(incident.getTitle())
                .description(incident.getDescription())
                .suggestedSeverity(incident.getSuggestedSeverity())
                .confirmedSeverity(incident.getConfirmedSeverity())
                .status(incident.getStatus())
                .credibilityScore(incident.getCredibilityScore())
                .corroborationCount(incident.getCorroborationCount())
                .submittedAt(incident.getSubmittedAt())
                .reviewedAt(incident.getReviewedAt())
                .duplicateOf(incident.getDuplicateOf())
                .build();
    }
}
