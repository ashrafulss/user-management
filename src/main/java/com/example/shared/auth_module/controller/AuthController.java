package com.example.shared.auth_module.controller;

import com.example.shared.auth_module.dto.ApiResponse;
import com.example.shared.auth_module.entity.User;
import com.example.shared.auth_module.entity.UserSession;
import com.example.shared.auth_module.repository.UserRepository;
import com.example.shared.auth_module.repository.UserSessionRepository;
import com.example.shared.auth_module.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID; // Added necessary UUID import

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
    public ResponseEntity<ApiResponse<UUID>> register(@RequestBody User user) {
        if (userRepository.findByMobile(user.getMobile()).isPresent()) {
            throw new IllegalArgumentException("Mobile number already exists!");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of("ROLE_USER"));
        }

        User saved = userRepository.save(user);
        return ResponseEntity.ok(ApiResponse.success("User registered successfully", saved.getId()));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Map<String, String>>> login(@RequestBody Map<String, String> request, HttpServletRequest servletRequest) {
        Optional<User> userOpt = userRepository.findByMobile(request.get("mobile"));

        if (userOpt.isPresent() && passwordEncoder.matches(request.get("password"), userOpt.get().getPassword())) {
            User user = userOpt.get();

            if (!"active".equalsIgnoreCase(user.getStatus())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("ACCOUNT_DISABLED", "Account status is " + user.getStatus()));
            }

            String token = jwtUtil.generateToken(user.getMobile(), user.getRoles());

            UserSession session = new UserSession();
            session.setUser(user);
            session.setTokenHash(jwtUtil.hashToken(token)); // Kept clean utility separation
            session.setIpAddress(servletRequest.getRemoteAddr());
            session.setUserAgent(servletRequest.getHeader("User-Agent"));
            session.setExpiresAt(LocalDateTime.now().plusHours(24));
            sessionRepository.save(session);

            return ResponseEntity.ok(ApiResponse.success("Login successful", Map.of("token", token)));
        }

        throw new SecurityException("Invalid mobile or password combination.");
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String header) {
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            sessionRepository.deleteByTokenHash(jwtUtil.hashToken(token));
            return ResponseEntity.ok(ApiResponse.success("Logged out successfully, session wiped.", null));
        }
        throw new IllegalArgumentException("Invalid authorization signature.");
    }
}