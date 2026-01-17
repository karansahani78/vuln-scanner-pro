package com.security.vulnscanner.service;

import com.security.vulnscanner.model.Scan;
import com.security.vulnscanner.model.Vulnerability;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReportGeneratorService {
    
    public String generateDeveloperReport(Scan scan, List<Vulnerability> vulnerabilities) {
        StringBuilder report = new StringBuilder();
        
        report.append("# Vulnerability Report for Developers\n");
        report.append(String.format("Scan Date: %s | Target: %s\n\n",
            scan.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE),
            scan.getTarget().getName()));
        
        // Group by severity
        Map<Vulnerability.Severity, List<Vulnerability>> bySeverity = vulnerabilities.stream()
            .collect(Collectors.groupingBy(Vulnerability::getSeverity));
        
        // Critical issues (P0)
        if (bySeverity.containsKey(Vulnerability.Severity.CRITICAL)) {
            report.append("## 🔴 P0 - Fix Immediately (")
                  .append(bySeverity.get(Vulnerability.Severity.CRITICAL).size())
                  .append(" issues)\n\n");
            
            int issueNumber = 1;
            for (Vulnerability vuln : bySeverity.get(Vulnerability.Severity.CRITICAL)) {
                report.append(formatDeveloperIssue(issueNumber++, vuln, "P0"));
            }
        }
        
        // High severity (P1)
        if (bySeverity.containsKey(Vulnerability.Severity.HIGH)) {
            report.append("\n## 🟠 P1 - Fix This Week (")
                  .append(bySeverity.get(Vulnerability.Severity.HIGH).size())
                  .append(" issues)\n\n");
            
            int issueNumber = 1;
            for (Vulnerability vuln : bySeverity.get(Vulnerability.Severity.HIGH)) {
                report.append(formatDeveloperIssue(issueNumber++, vuln, "P1"));
            }
        }
        
        // Summary
        report.append("\n## 📊 Summary\n");
        report.append(String.format("- Total Issues: %d\n", vulnerabilities.size()));
        report.append(String.format("- P0 (Critical): %d\n", 
            bySeverity.getOrDefault(Vulnerability.Severity.CRITICAL, List.of()).size()));
        report.append(String.format("- P1 (High): %d\n",
            bySeverity.getOrDefault(Vulnerability.Severity.HIGH, List.of()).size()));
        report.append(String.format("- P2 (Medium): %d\n",
            bySeverity.getOrDefault(Vulnerability.Severity.MEDIUM, List.of()).size()));
        report.append(String.format("- P3 (Low): %d\n",
            bySeverity.getOrDefault(Vulnerability.Severity.LOW, List.of()).size()));
        
        report.append("\n**Recommended Action Plan:**\n");
        if (bySeverity.containsKey(Vulnerability.Severity.CRITICAL)) {
            report.append("1. Today: Fix P0 issues (high priority)\n");
        }
        if (bySeverity.containsKey(Vulnerability.Severity.HIGH)) {
            report.append("2. This Week: Fix P1 issues\n");
        }
        report.append("3. This Sprint: Address P2 issues\n");
        report.append("4. Next Sprint: Handle P3 issues\n");
        
        return report.toString();
    }
    
    private String formatDeveloperIssue(int number, Vulnerability vuln, String priority) {
        StringBuilder issue = new StringBuilder();
        
        issue.append(String.format("### %d. %s\n", number, vuln.getTitle()));
        issue.append(String.format("**Endpoint:** `%s`\n", vuln.getAffectedUrl()));
        issue.append(String.format("**Category:** %s | **CVSS:** %.1f | **Priority:** %s\n\n",
            vuln.getCategory(), vuln.getCvssScore(), priority));
        
        issue.append("**Issue Description:**\n");
        issue.append(vuln.getDescription()).append("\n\n");
        
        if (vuln.getEvidence() != null && !vuln.getEvidence().isEmpty()) {
            issue.append("**Evidence:**\n```\n");
            issue.append(vuln.getEvidence());
            issue.append("\n```\n\n");
        }
        
        if (vuln.getRemediation() != null && !vuln.getRemediation().isEmpty()) {
            issue.append("**How to Fix:**\n");
            issue.append(vuln.getRemediation()).append("\n\n");
        }
        
        issue.append("**Estimated Fix Time:** ");
        issue.append(estimateFixTime(vuln)).append("\n\n");
        
        issue.append("---\n\n");
        
        return issue.toString();
    }
    
    public String generateExecutiveReport(Scan scan, List<Vulnerability> vulnerabilities) {
        StringBuilder report = new StringBuilder();
        
        report.append("# Executive Security Summary\n");
        report.append(String.format("Application: %s | Date: %s\n\n",
            scan.getTarget().getName(),
            scan.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE)));
        
        // Overall risk score
        double riskScore = scan.getRiskScore() != null ? scan.getRiskScore() : 5.0;
        String riskLevel = riskScore >= 7.0 ? "HIGH" : riskScore >= 4.0 ? "MEDIUM" : "LOW";
        
        report.append(String.format("## 🎯 Overall Risk Score: %.1f/10 (%s)\n\n", riskScore, riskLevel));
        
        // Executive summary
        report.append("### Executive Summary\n");
        report.append(String.format(
            "Security scan identified **%d vulnerabilities** across the application, including " +
            "**%d critical issues** that require immediate attention.\n\n",
            vulnerabilities.size(), scan.getCriticalCount()));
        
        // Business impact
        report.append("### Business Impact\n");
        if (scan.getCriticalCount() > 0) {
            report.append("- **CRITICAL RISK:** Potential for data breach, unauthorized access, or system compromise\n");
            report.append("- **Financial Risk:** Estimated $1M - $5M potential breach cost\n");
            report.append("- **Regulatory Risk:** Potential compliance violations (PCI-DSS, GDPR)\n\n");
        } else if (scan.getHighCount() > 0) {
            report.append("- **ELEVATED RISK:** Security weaknesses present but not immediately exploitable\n");
            report.append("- **Remediation Timeline:** Should be addressed within 1-2 weeks\n\n");
        } else {
            report.append("- **MANAGEABLE RISK:** No critical vulnerabilities detected\n");
            report.append("- Continue with planned security maintenance cycle\n\n");
        }
        
        // Risk breakdown
        report.append("### Risk Breakdown\n\n");
        report.append("```\n");
        report.append(String.format("┌─────────────────────────────────────┐\n"));
        report.append(String.format("│ CRITICAL: %-2d issues              │\n", scan.getCriticalCount()));
        report.append(String.format("│ HIGH:     %-2d issues              │\n", scan.getHighCount()));
        report.append(String.format("│ MEDIUM:   %-2d issues              │\n", scan.getMediumCount()));
        report.append(String.format("│ LOW:      %-2d issues              │\n", scan.getLowCount()));
        report.append(String.format("└─────────────────────────────────────┘\n"));
        report.append("```\n\n");
        
        // Recommended actions
        report.append("### Recommended Actions\n\n");
        
        if (scan.getCriticalCount() > 0) {
            report.append("1. **Immediate (24 hours)**: Fix critical vulnerabilities\n");
            report.append("   - Cost: 4-8 developer hours\n");
            report.append("   - Impact: Eliminates 70% of breach risk\n\n");
        }
        
        if (scan.getHighCount() > 0) {
            report.append("2. **This Week**: Address high-priority issues\n");
            report.append("   - Cost: 2-3 developer days\n");
            report.append("   - Impact: Achieves baseline security posture\n\n");
        }
        
        report.append("3. **This Month**: Implement ongoing security program\n");
        report.append("   - Cost: $30K - $50K annual\n");
        report.append("   - Impact: 80% reduction in future vulnerabilities\n\n");
        
        // ROI
        report.append("### Return on Investment\n");
        int devHours = estimateTotalFixTime(vulnerabilities);
        double fixCost = devHours * 150; // $150/hour developer rate
        
        report.append(String.format("- Cost to fix all issues: $%.0f (%d dev hours)\n", fixCost, devHours));
        report.append("- Cost of potential breach: $1M - $5M\n");
        report.append(String.format("- ROI: %.0f%%\n", (2000000 / fixCost) * 100));
        report.append("- Risk reduction: 85%\n\n");
        
        return report.toString();
    }
    
    public String generateComplianceReport(Scan scan, List<Vulnerability> vulnerabilities) {
        StringBuilder report = new StringBuilder();
        
        report.append("# Compliance Security Report\n");
        report.append(String.format("Application: %s | Date: %s\n\n",
            scan.getTarget().getName(),
            scan.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE)));
        
        // Compliance frameworks affected
        report.append("## Compliance Impact Assessment\n\n");
        
        boolean hasPCIIssues = vulnerabilities.stream()
            .anyMatch(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL ||
                          (v.getCategory() != null && v.getCategory().toLowerCase().contains("injection")));
        
        if (hasPCIIssues) {
            report.append("### ❌ PCI-DSS Compliance\n");
            report.append("- **Status:** NON-COMPLIANT\n");
            report.append("- **Requirements Affected:** 6.5 (Secure Coding), 11.3 (Vulnerability Scans)\n");
            report.append("- **Action Required:** Immediate remediation required for compliance\n\n");
        }
        
        boolean hasGDPRIssues = vulnerabilities.stream()
            .anyMatch(v -> v.getDescription() != null && 
                          v.getDescription().toLowerCase().contains("data exposure"));
        
        if (hasGDPRIssues) {
            report.append("### ⚠️ GDPR Compliance\n");
            report.append("- **Status:** AT RISK\n");
            report.append("- **Articles Affected:** Article 32 (Security of Processing)\n");
            report.append("- **Action Required:** Address data protection vulnerabilities\n\n");
        }
        
        // Vulnerability mapping to controls
        report.append("## Control Failures\n\n");
        
        Map<String, Integer> categoryCount = vulnerabilities.stream()
            .collect(Collectors.groupingBy(
                v -> v.getCategory() != null ? v.getCategory() : "Other",
                Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
            ));
        
        for (Map.Entry<String, Integer> entry : categoryCount.entrySet()) {
            report.append(String.format("- **%s:** %d finding(s)\n", entry.getKey(), entry.getValue()));
        }
        
        return report.toString();
    }
    
    private String estimateFixTime(Vulnerability vuln) {
        if (vuln.getSeverity() == Vulnerability.Severity.CRITICAL) {
            return "30-60 minutes";
        } else if (vuln.getSeverity() == Vulnerability.Severity.HIGH) {
            return "1-2 hours";
        } else if (vuln.getSeverity() == Vulnerability.Severity.MEDIUM) {
            return "2-4 hours";
        } else {
            return "4-8 hours";
        }
    }
    
    private int estimateTotalFixTime(List<Vulnerability> vulnerabilities) {
        int total = 0;
        for (Vulnerability vuln : vulnerabilities) {
            if (vuln.getSeverity() == Vulnerability.Severity.CRITICAL) {
                total += 1; // 1 hour
            } else if (vuln.getSeverity() == Vulnerability.Severity.HIGH) {
                total += 2; // 2 hours
            } else if (vuln.getSeverity() == Vulnerability.Severity.MEDIUM) {
                total += 3; // 3 hours
            } else {
                total += 6; // 6 hours
            }
        }
        return total;
    }
    
    public enum ReportAudience {
        DEVELOPER,
        EXECUTIVE,
        SECURITY_TEAM,
        COMPLIANCE
    }
}
