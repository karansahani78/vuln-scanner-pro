package com.security.vulnscanner.controller;

import com.security.vulnscanner.dto.AuthRequest;
import com.security.vulnscanner.dto.RegisterRequest;
import com.security.vulnscanner.model.User;
import com.security.vulnscanner.repository.UserRepository;
import com.security.vulnscanner.security.JwtUtil;
import com.security.vulnscanner.service.EmailService;
import com.security.vulnscanner.util.OtpUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final EmailService emailService;
    private final OtpUtil otpUtil;

    // ===============================
    // STEP 1: REQUEST OTP
    // ===============================
    @PostMapping("/register/request-code")
    public ResponseEntity<?> requestVerificationCode(@RequestBody Map<String, String> body) {

        String email = body.get("email");
        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }

        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
        }

        String code = otpUtil.generateOtp();

        User user = new User();
        user.setEmail(email);
        user.setEmailVerificationCode(code);
        user.setEmailVerificationExpiry(LocalDateTime.now().plusMinutes(10));
        user.setEmailVerified(false);
        user.setActive(false);

        userRepository.save(user);
        emailService.sendVerificationCode(email, code);

        return ResponseEntity.ok(Map.of("message", "Verification code sent to email"));
    }

    // ===============================
    // STEP 2: VERIFY OTP + REGISTER
    // ===============================
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request,
                                      @RequestParam String code) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email not verified"));

        if (!code.equals(user.getEmailVerificationCode())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid verification code"));
        }

        if (user.getEmailVerificationExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Verification code expired"));
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
        }

        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());
        user.setOrganization(request.getOrganization());
        user.setRoles(Set.of("ROLE_USER"));
        user.setActive(true);
        user.setEmailVerified(true);
        user.setEmailVerificationCode(null);
        user.setEmailVerificationExpiry(null);

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully"));
    }

    // ===============================
    // LOGIN
    // ===============================
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request) {

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!user.isEmailVerified()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Please verify email first"));
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "type", "Bearer",
                "username", user.getUsername(),
                "email", user.getEmail(),
                "roles", user.getRoles()
        ));
    }

    // ===============================
    // TOKEN VALIDATION
    // ===============================
    @GetMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String header) {

        String token = header.substring(7);
        String username = jwtUtil.extractUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        return jwtUtil.validateToken(token, userDetails)
                ? ResponseEntity.ok(Map.of("valid", true))
                : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false));
    }
}
