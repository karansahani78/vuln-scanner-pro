package com.security.vulnscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "scans")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "target_id")
    @JsonIgnoreProperties({"scans", "user"})
    private Target target;

    @Enumerated(EnumType.STRING)
    private ScanStatus status;

    @Enumerated(EnumType.STRING)
    private ScanType scanType;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "duration_seconds")
    private Long durationSeconds;

    @Column(name = "total_vulnerabilities")
    private Integer totalVulnerabilities = 0;

    @Column(name = "critical_count")
    private Integer criticalCount = 0;

    @Column(name = "high_count")
    private Integer highCount = 0;

    @Column(name = "medium_count")
    private Integer mediumCount = 0;

    @Column(name = "low_count")
    private Integer lowCount = 0;

    @Column(name = "info_count")
    private Integer infoCount = 0;

    @Column(name = "risk_score")
    private Double riskScore = 0.0;

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    @com.fasterxml.jackson.annotation.JsonIgnore
    private Set<Vulnerability> vulnerabilities = new HashSet<>();

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public enum ScanStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        CANCELLED
    }

    public enum ScanType {
        QUICK_SCAN,
        FULL_SCAN,
        CUSTOM_SCAN
    }
}
