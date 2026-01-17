package com.security.vulnscanner.service;

import com.security.vulnscanner.exception.ScannerExceptions.*;
import com.security.vulnscanner.model.Scan;
import com.security.vulnscanner.model.Target;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * CRITICAL: Authorization service for multi-tenant security
 * Prevents users from accessing each other's data - essential for SaaS
 * 
 * Business Impact:
 * - Prevents data breaches between customers
 * - Enables safe multi-tenancy
 * - Required for compliance (SOC2, ISO27001)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserRepository userRepository;

    /**
     * Get authenticated user or throw 401
     * Centralizes user lookup to avoid repetition
     */
    public User getAuthenticatedUser(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            throw new ResourceForbiddenException("Authentication required");
        }
        
        return userRepository.findByUsername(authentication.getName())
            .orElseThrow(() -> new ResourceForbiddenException("User not found"));
    }

    /**
     * Verify user owns the target
     * Prevents unauthorized scan creation on targets owned by other users
     * 
     * Security: Returns 403 instead of revealing target existence
     */
    public void verifyTargetOwnership(Target target, User user) {
        if (!target.getUser().getId().equals(user.getId())) {
            log.warn("User {} attempted to access target {} owned by user {}", 
                user.getId(), target.getId(), target.getUser().getId());
            throw new ResourceForbiddenException("Access denied to this target");
        }
    }

    /**
     * Verify user owns the scan
     * Prevents viewing scans/vulnerabilities from other users
     * 
     * Security: Returns 403 for ownership violations, 404 for non-existent
     */
    public void verifyScanOwnership(Scan scan, User user) {
        if (!scan.getTarget().getUser().getId().equals(user.getId())) {
            log.warn("User {} attempted to access scan {} owned by user {}", 
                user.getId(), scan.getId(), scan.getTarget().getUser().getId());
            throw new ResourceForbiddenException("Access denied to this scan");
        }
    }
}
