package com.security.vulnscanner.controller;

import com.security.vulnscanner.model.Scan;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.model.Vulnerability;
import com.security.vulnscanner.service.AuthorizationService;
import com.security.vulnscanner.service.ReportGeneratorService;
import com.security.vulnscanner.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
public class ReportController {
    
    private final ScanService scanService;
    private final ReportGeneratorService reportGenerator;
    private final AuthorizationService authorizationService;
    
    @GetMapping("/{scanId}/developer")
    public ResponseEntity<String> getDeveloperReport(
            @PathVariable Long scanId,
            Authentication authentication) {
        
        User user = authorizationService.getAuthenticatedUser(authentication);
        Scan scan = scanService.getScanById(scanId, user);
        List<Vulnerability> vulnerabilities = scanService.getVulnerabilitiesByScanId(scanId, user);
        
        String report = reportGenerator.generateDeveloperReport(scan, vulnerabilities);
        
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_MARKDOWN)
            .header(HttpHeaders.CONTENT_DISPOSITION, 
                "attachment; filename=developer-report-" + scanId + ".md")
            .body(report);
    }
    
    @GetMapping("/{scanId}/executive")
    public ResponseEntity<String> getExecutiveReport(
            @PathVariable Long scanId,
            Authentication authentication) {
        
        User user = authorizationService.getAuthenticatedUser(authentication);
        Scan scan = scanService.getScanById(scanId, user);
        List<Vulnerability> vulnerabilities = scanService.getVulnerabilitiesByScanId(scanId, user);
        
        String report = reportGenerator.generateExecutiveReport(scan, vulnerabilities);
        
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_MARKDOWN)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=executive-report-" + scanId + ".md")
            .body(report);
    }
    
    @GetMapping("/{scanId}/compliance")
    public ResponseEntity<String> getComplianceReport(
            @PathVariable Long scanId,
            Authentication authentication) {
        
        User user = authorizationService.getAuthenticatedUser(authentication);
        Scan scan = scanService.getScanById(scanId, user);
        List<Vulnerability> vulnerabilities = scanService.getVulnerabilitiesByScanId(scanId, user);
        
        String report = reportGenerator.generateComplianceReport(scan, vulnerabilities);
        
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_MARKDOWN)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=compliance-report-" + scanId + ".md")
            .body(report);
    }
}
