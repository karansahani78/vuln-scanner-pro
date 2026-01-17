package com.security.vulnscanner.service;

import com.security.vulnscanner.dto.TargetRequest;
import com.security.vulnscanner.model.Target;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.repository.TargetRepository;
import com.security.vulnscanner.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class TargetService {

    private final TargetRepository targetRepository;
    private final UserRepository userRepository;

    @Transactional
    public Target createTarget(TargetRequest request, String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));

        Target target = new Target();
        target.setName(request.getName());
        target.setUrl(normalizeUrl(request.getUrl()));
        target.setType(request.getType());
        target.setDescription(request.getDescription());
        target.setUser(user);

        log.info("Creating new target: {} for user: {}", request.getName(), username);
        return targetRepository.save(target);
    }

    public Target getTargetById(Long id) {
        return targetRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Target not found"));
    }

    public List<Target> getTargetsByUserId(Long userId) {
        return targetRepository.findByUserId(userId);
    }

    @Transactional
    public Target updateTarget(Long id, TargetRequest request) {
        Target target = getTargetById(id);
        target.setName(request.getName());
        target.setUrl(normalizeUrl(request.getUrl()));
        target.setType(request.getType());
        target.setDescription(request.getDescription());
        
        return targetRepository.save(target);
    }

    @Transactional
    public void deleteTarget(Long id) {
        targetRepository.deleteById(id);
        log.info("Deleted target with ID: {}", id);
    }

    private String normalizeUrl(String url) {
        url = url.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        return url;
    }
}
