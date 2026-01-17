package com.security.vulnscanner.dto;

import com.security.vulnscanner.model.Scan;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ScanResponse {
    private Long id;
    private Long targetId;
    private String targetName;
    private String targetUrl;
    private String status;
    private String scanType;
    private LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private Long durationSeconds;
    private Integer totalVulnerabilities;
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Integer infoCount;
    private Double riskScore;
    private String errorMessage;
    private LocalDateTime createdAt;

    public static ScanResponse fromEntity(Scan scan) {
        ScanResponse response = new ScanResponse();
        response.setId(scan.getId());
        response.setTargetId(scan.getTarget().getId());
        response.setTargetName(scan.getTarget().getName());
        response.setTargetUrl(scan.getTarget().getUrl());
        response.setStatus(scan.getStatus().toString());
        response.setScanType(scan.getScanType().toString());
        response.setStartedAt(scan.getStartedAt());
        response.setCompletedAt(scan.getCompletedAt());
        response.setDurationSeconds(scan.getDurationSeconds());
        response.setTotalVulnerabilities(scan.getTotalVulnerabilities());
        response.setCriticalCount(scan.getCriticalCount());
        response.setHighCount(scan.getHighCount());
        response.setMediumCount(scan.getMediumCount());
        response.setLowCount(scan.getLowCount());
        response.setInfoCount(scan.getInfoCount());
        response.setRiskScore(scan.getRiskScore());
        response.setErrorMessage(scan.getErrorMessage());
        response.setCreatedAt(scan.getCreatedAt());
        return response;
    }
}
