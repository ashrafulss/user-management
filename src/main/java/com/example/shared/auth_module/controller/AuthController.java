package com.example.shared.auth_module.controller;

import com.example.shared.auth_module.entity.User;
import com.example.shared.auth_module.entity.UserSession;
import com.example.shared.auth_module.repository.UserRepository;
import com.example.shared.auth_module.repository.UserSessionRepository;
import com.example.shared.auth_module.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository, UserSessionRepository sessionRepository,
                          PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userRepository.findByMobile(user.getMobile()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Mobile already registered"));
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of("ROLE_USER"));
        }
        User saved = userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "User created", "id", saved.getId()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request, HttpServletRequest servletRequest) {
        Optional<User> userOpt = userRepository.findByMobile(request.get("mobile"));
        if (userOpt.isPresent() && passwordEncoder.matches(request.get("password"), userOpt.get().getPassword())) {
            User user = userOpt.get();

            if (!"active".equals(user.getStatus())) {
                return ResponseEntity.status(403).body(Map.of("error", "Account status is " + user.getStatus()));
            }

            String token = jwtUtil.generateToken(user.getMobile(), user.getRoles());

            UserSession session = new UserSession();
            session.setUser(user);
            session.setTokenHash(hashToken(token));
            session.setIpAddress(servletRequest.getRemoteAddr());
            session.setUserAgent(servletRequest.getHeader("User-Agent"));
            session.setExpiresAt(LocalDateTime.now().plusHours(24));
            sessionRepository.save(session);

            return ResponseEntity.ok(Map.of("token", token));
        }
        return ResponseEntity.status(401).body(Map.of("error", "Bad credentials"));
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String header) {
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            sessionRepository.deleteByTokenHash(hashToken(token));
            return ResponseEntity.ok(Map.of("message", "Logged out, session invalidated"));
        }
        return ResponseEntity.badRequest().build();
    }

    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return "";
        }
    }
}