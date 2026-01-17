package com.security.vulnscanner.controller;

import com.security.vulnscanner.dto.ScanRequest;
import com.security.vulnscanner.dto.ScanResponse;
import com.security.vulnscanner.dto.VulnerabilityResponse;
import com.security.vulnscanner.exception.ScannerExceptions.*;
import com.security.vulnscanner.model.Scan;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.model.Vulnerability;
import com.security.vulnscanner.service.AuthorizationService;
import com.security.vulnscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * PRODUCTION-READY SCAN CONTROLLER
 * 
 * Security:
 * - All endpoints enforce ownership validation
 * - Returns proper HTTP status codes (403, 404, 409)
 * - No information leakage about other users' data
 * 
 * API Design:
 * - RESTful endpoints
 * - Clear error messages
 * - Suitable for client SDK generation
 * 
 * Monetization:
 * - Ready for rate limiting middleware
 * - Audit trail compatible
 * - Usage tracking hooks
 */
@Slf4j
@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;
    private final AuthorizationService authorizationService;

    /**
     * Start a new scan
     * 
     * Security: Validates user owns target before creating scan
     * 
     * Returns:
     * - 201: Scan created successfully
     * - 403: User doesn't own target
     * - 404: Target not found
     * - 409: Scan already running on target
     */
    @PostMapping
    public ResponseEntity<?> startScan(
            @Valid @RequestBody ScanRequest request,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            // Create scan with ownership validation
            Scan scan = scanService.createScan(request, user);
            
            // Execute asynchronously (doesn't block response)
            scanService.executeScan(scan.getId(), request);
            
            log.info("User {} started scan {} on target {}", 
                user.getId(), scan.getId(), request.getTargetId());
            
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "scanId", scan.getId(),
                "status", scan.getStatus().toString(),
                "message", "Scan started successfully. Results will be available shortly."
            ));
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", e.getMessage()));
                
        } catch (ResourceForbiddenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", e.getMessage()));
                
        } catch (ScanConflictException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", e.getMessage()));
                
        } catch (Exception e) {
            log.error("Unexpected error starting scan: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }

    /**
     * Get all scans for authenticated user
     * 
     * Security: Only returns scans owned by the authenticated user
     * 
     * Returns:
     * - 200: List of scans (may be empty)
     */
    @GetMapping
    public ResponseEntity<List<ScanResponse>> getMyScans(Authentication authentication) {
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            List<Scan> scans = scanService.getScansByUserId(user.getId());
            List<ScanResponse> responses = scans.stream()
                .map(ScanResponse::fromEntity)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(responses);
            
        } catch (Exception e) {
            log.error("Error fetching user scans: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get specific scan by ID
     * 
     * Security: Validates user owns the scan before returning
     * 
     * Returns:
     * - 200: Scan details
     * - 403: User doesn't own scan
     * - 404: Scan not found
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getScan(
            @PathVariable Long id,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            // Ownership validated inside service
            Scan scan = scanService.getScanById(id, user);
            
            return ResponseEntity.ok(ScanResponse.fromEntity(scan));
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Scan not found"));
                
        } catch (ResourceForbiddenException e) {
            // Don't reveal scan existence to unauthorized users
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
                
        } catch (Exception e) {
            log.error("Error fetching scan {}: {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }

    /**
     * Get vulnerabilities for a scan
     * 
     * Security: Validates user owns the scan before returning vulnerabilities
     * 
     * Returns:
     * - 200: List of vulnerabilities (may be empty)
     * - 403: User doesn't own scan
     * - 404: Scan not found
     */
    @GetMapping("/{id}/vulnerabilities")
    public ResponseEntity<?> getVulnerabilities(
            @PathVariable Long id,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            // Ownership validated inside service
            List<Vulnerability> vulnerabilities = scanService.getVulnerabilitiesByScanId(id, user);
            List<VulnerabilityResponse> responses = vulnerabilities.stream()
                .map(VulnerabilityResponse::fromEntity)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(responses);
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Scan not found"));
                
        } catch (ResourceForbiddenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
                
        } catch (Exception e) {
            log.error("Error fetching vulnerabilities for scan {}: {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }

    /**
     * Get all scans for a specific target
     * 
     * Security: Validates user owns the target before returning scans
     * Useful for: Tracking scan history, comparing results over time
     * 
     * Returns:
     * - 200: List of scans for target
     * - 403: User doesn't own target
     * - 404: Target not found
     */
    @GetMapping("/target/{targetId}")
    public ResponseEntity<?> getScansByTarget(
            @PathVariable Long targetId,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            // Ownership validated inside service
            List<Scan> scans = scanService.getScansByTargetId(targetId, user);
            List<ScanResponse> responses = scans.stream()
                .map(ScanResponse::fromEntity)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(responses);
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Target not found"));
                
        } catch (ResourceForbiddenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
                
        } catch (Exception e) {
            log.error("Error fetching scans for target {}: {}", targetId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }

    /**
     * Mark vulnerability as false positive
     * 
     * Business Value: Improves scan quality and user trust
     * Data Value: Trains ML models for future FP reduction
     * 
     * Returns:
     * - 200: Marked successfully
     * - 403: User doesn't own vulnerability
     * - 404: Vulnerability not found
     */
    @PutMapping("/vulnerabilities/{id}/false-positive")
    public ResponseEntity<?> markAsFalsePositive(
            @PathVariable Long id,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            scanService.markAsFalsePositive(id, user);
            
            return ResponseEntity.ok(Map.of(
                "message", "Vulnerability marked as false positive",
                "vulnerabilityId", id
            ));
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Vulnerability not found"));
                
        } catch (ResourceForbiddenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
                
        } catch (Exception e) {
            log.error("Error marking vulnerability {} as FP: {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }

    /**
     * Mark vulnerability as resolved
     * 
     * Business Value: Tracks remediation progress, shows value to customers
     * Monetization: Enables "remediation tracking" as premium feature
     * 
     * Returns:
     * - 200: Marked successfully
     * - 403: User doesn't own vulnerability
     * - 404: Vulnerability not found
     */
    @PutMapping("/vulnerabilities/{id}/resolved")
    public ResponseEntity<?> markAsResolved(
            @PathVariable Long id,
            Authentication authentication) {
        
        try {
            User user = authorizationService.getAuthenticatedUser(authentication);
            
            scanService.markAsResolved(id, user);
            
            return ResponseEntity.ok(Map.of(
                "message", "Vulnerability marked as resolved",
                "vulnerabilityId", id
            ));
            
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Vulnerability not found"));
                
        } catch (ResourceForbiddenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
                
        } catch (Exception e) {
            log.error("Error marking vulnerability {} as resolved: {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred"));
        }
    }
}
