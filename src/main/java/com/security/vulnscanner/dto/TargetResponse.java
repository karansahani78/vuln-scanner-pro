package com.security.vulnscanner.dto;

import com.security.vulnscanner.model.Target;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class TargetResponse {
    private Long id;
    private String name;
    private String url;
    private String type;
    private String description;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static TargetResponse fromEntity(Target target) {
        TargetResponse response = new TargetResponse();
        response.setId(target.getId());
        response.setName(target.getName());
        response.setUrl(target.getUrl());
        response.setType(target.getType().toString());
        response.setDescription(target.getDescription());
        response.setCreatedAt(target.getCreatedAt());
        response.setUpdatedAt(target.getUpdatedAt());
        return response;
    }
}
