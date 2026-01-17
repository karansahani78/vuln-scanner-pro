package com.security.vulnscanner.controller;

import com.security.vulnscanner.dto.TargetRequest;
import com.security.vulnscanner.dto.TargetResponse;
import com.security.vulnscanner.model.Target;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.repository.UserRepository;
import com.security.vulnscanner.service.TargetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/targets")
@RequiredArgsConstructor
public class TargetController {

    private final TargetService targetService;
    private final UserRepository userRepository;

    @PostMapping
    public ResponseEntity<TargetResponse> createTarget(
            @Valid @RequestBody TargetRequest request,
            Authentication authentication) {
        
        Target target = targetService.createTarget(request, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(TargetResponse.fromEntity(target));
    }

    @GetMapping
    public ResponseEntity<List<TargetResponse>> getMyTargets(Authentication authentication) {
        User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
        List<Target> targets = targetService.getTargetsByUserId(user.getId());
        List<TargetResponse> responses = targets.stream()
            .map(TargetResponse::fromEntity)
            .collect(Collectors.toList());
        return ResponseEntity.ok(responses);
    }

    @GetMapping("/{id}")
    public ResponseEntity<TargetResponse> getTarget(@PathVariable Long id) {
        Target target = targetService.getTargetById(id);
        return ResponseEntity.ok(TargetResponse.fromEntity(target));
    }

    @PutMapping("/{id}")
    public ResponseEntity<TargetResponse> updateTarget(
            @PathVariable Long id,
            @Valid @RequestBody TargetRequest request) {
        
        Target target = targetService.updateTarget(id, request);
        return ResponseEntity.ok(TargetResponse.fromEntity(target));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteTarget(@PathVariable Long id) {
        targetService.deleteTarget(id);
        return ResponseEntity.noContent().build();
    }
}
