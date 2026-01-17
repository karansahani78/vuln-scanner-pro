package com.security.vulnscanner.controller;

import com.security.vulnscanner.model.TechnologyStack;
import com.security.vulnscanner.service.TechnologyDetector;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/technology")
@RequiredArgsConstructor
public class TechnologyController {
    
    private final TechnologyDetector technologyDetector;
    
    @PostMapping("/detect")
    public ResponseEntity<TechnologyStack> detectTechnology(@RequestBody DetectRequest request) {
        TechnologyStack stack = technologyDetector.detectStack(request.getUrl());
        return ResponseEntity.ok(stack);
    }
    
    public static class DetectRequest {
        @NotBlank
        private String url;
        
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
    }
}
