package com.security.vulnscanner.dto;

import com.security.vulnscanner.model.Target;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class TargetRequest {
    
    @NotBlank(message = "Target name is required")
    private String name;
    
    @NotBlank(message = "Target URL is required")
    private String url;
    
    @NotNull(message = "Target type is required")
    private Target.TargetType type;
    
    private String description;
}
