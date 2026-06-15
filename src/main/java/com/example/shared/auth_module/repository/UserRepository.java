package com.example.shared.auth_module.repository;


import com.example.shared.auth_module.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByMobile(String mobile);
}