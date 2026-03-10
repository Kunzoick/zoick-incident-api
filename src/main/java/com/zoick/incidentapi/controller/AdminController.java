package com.zoick.incidentapi.controller;

import com.zoick.incidentapi.dto.request.ReviewIncidentRequest;
import com.zoick.incidentapi.dto.response.IncidentResponse;
import com.zoick.incidentapi.dto.response.PagedResponse;
import com.zoick.incidentapi.service.IncidentService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import com.zoick.incidentapi.dto.request.TrustOverrideRequest;
import com.zoick.incidentapi.service.TrustScoreService;
import com.zoick.incidentapi.repository.UserRepository;

/**
 * Admin facing endpoints-> all endpoints require Admin role-> enforced by securityConfig, fixed rate limit applies-> not trust-score-derived.
 * Zero business logic here-> delegates entirely to IncidentService
 */
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final IncidentService incidentService;
    private final TrustScoreService trustScoreService;
    private final UserRepository userRepository;
    // view all incicents-> ordered by credibility score descending then severity
    @GetMapping("/incidents")
    public ResponseEntity<PagedResponse<IncidentResponse>> getAllIncidents(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int pageSize
    ) {
        var result = incidentService.getAllIncidents(page, pageSize);
        return ResponseEntity.ok(
                PagedResponse.from(result, IncidentResponse::from));
    }

    /**
     * View a single incident — no ownership restriction.
     */
    @GetMapping("/incidents/{id}")
    public ResponseEntity<IncidentResponse> getIncident(
            @PathVariable String id
    ) {
        var incident = incidentService.getIncidentAsAdmin(id);
        return ResponseEntity.ok(IncidentResponse.from(incident));
    }

    /**
     * Review an incident — set confirmed severity and status.
     * Triggers trust score event on submitter per Phase 3.
     * Valid transitions: PENDING → UNDER_REVIEW → RESOLVED | REJECTED
     */
    @PatchMapping("/incidents/{id}/review")
    public ResponseEntity<IncidentResponse> review(
            @PathVariable String id,
            @Valid @RequestBody ReviewIncidentRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest
    ) {
        var incident = incidentService.review(
                id,
                userDetails.getUsername(),
                request.getConfirmedSeverity(),
                request.getStatus(),
                httpRequest
        );
        return ResponseEntity.ok(IncidentResponse.from(incident));
    }

    /**
     * Escalate an incident.
     * Valid from PENDING or UNDER_REVIEW only.
     */
    @PatchMapping("/incidents/{id}/escalate")
    public ResponseEntity<IncidentResponse> escalate(
            @PathVariable String id,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest
    ) {
        var incident = incidentService.escalate(
                id,
                userDetails.getUsername(),
                httpRequest
        );
        return ResponseEntity.ok(IncidentResponse.from(incident));
    }
    @PatchMapping("/users/{id}/trust")
    public ResponseEntity<Void> overrideTrust(@PathVariable String id, @Valid @RequestBody TrustOverrideRequest request,
                                              @AuthenticationPrincipal UserDetails userDetails, HttpServletRequest httpRequest){
        var user= userRepository.findById(id).orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("User not found"));
        trustScoreService.adminOverride(user, request.getNewScore(), userDetails.getUsername(), httpRequest);
        return ResponseEntity.noContent().build();
    }
}
