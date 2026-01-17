package com.security.vulnscanner.scanner;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanConfig {
    private boolean includeSubdomains;
    private boolean checkSSL;
    private boolean detectCMS;
    private boolean scanPorts;
    private Integer maxDepth;
    private Integer timeoutSeconds;
    private String userAgent;
}
