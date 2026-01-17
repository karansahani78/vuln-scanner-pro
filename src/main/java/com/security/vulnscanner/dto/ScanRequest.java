package com.security.vulnscanner.dto;

import com.security.vulnscanner.model.Scan;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class ScanRequest {
    
    @NotNull(message = "Target ID is required")
    private Long targetId;
    
    @NotNull(message = "Scan type is required")
    private Scan.ScanType scanType;
    
    private boolean includeSubdomains = false;
    private boolean checkSSL = true;
    private boolean detectCMS = true;
    private boolean scanPorts = false;
    private Integer maxDepth = 3;
}
