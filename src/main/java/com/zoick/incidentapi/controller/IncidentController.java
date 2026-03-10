package com.zoick.incidentapi.controller;

import com.zoick.incidentapi.dto.request.SubmitIncidentRequest;
import com.zoick.incidentapi.dto.response.IncidentResponse;
import com.zoick.incidentapi.dto.response.PagedResponse;
import com.zoick.incidentapi.service.IncidentService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * User-facing incident endpoints.
 *
 * All endpoints require authentication.
 * Ownership is enforced in the service layer.
 * Zero business logic here — delegates entirely to IncidentService.
 */
@RestController
@RequestMapping("/api/v1/incidents")
@RequiredArgsConstructor
public class IncidentController {
    private final IncidentService incidentService;

    /**
     * Submit a new incident report.
     * Trust tier check and duplicate detection happen in service.
     * Returns 201 Created with the created incident.
     */
    @PostMapping
    public ResponseEntity<IncidentResponse> submit(
            @Valid @RequestBody SubmitIncidentRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest
    ) {
        var incident = incidentService.submit(
                userDetails.getUsername(),
                request.getTitle(),
                request.getDescription(),
                request.getSuggestedSeverity(),
                httpRequest
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(IncidentResponse.from(incident));
    }

    /**
     * Get own incidents — paginated.
     * Only returns incidents belonging to the caller.
     */
    @GetMapping
    public ResponseEntity<PagedResponse<IncidentResponse>> getOwn(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int pageSize
    ) {
        var result = incidentService.getOwnIncidents(
                userDetails.getUsername(), page, pageSize);

        return ResponseEntity.ok(
                PagedResponse.from(result, IncidentResponse::from));
    }

    /**
     * Get a single own incident by ID.
     * Returns 403 ACCESS_DENIED if not owner — never 404.
     */
    @GetMapping("/{id}")
    public ResponseEntity<IncidentResponse> getOne(
            @PathVariable String id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        var incident = incidentService.getOwnIncident(
                id, userDetails.getUsername());

        return ResponseEntity.ok(IncidentResponse.from(incident));
    }
}
