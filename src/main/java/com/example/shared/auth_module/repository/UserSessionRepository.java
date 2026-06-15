package com.example.shared.auth_module.repository;

import com.example.shared.auth_module.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    Optional<UserSession> findByTokenHashAndExpiresAtAfterAndStatus(String tokenHash, LocalDateTime now, String status);
    void deleteByTokenHash(String tokenHash);
}