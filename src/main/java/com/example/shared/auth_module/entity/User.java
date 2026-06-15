package com.example.shared.auth_module.entity;

import com.example.shared.auth_module.entity.base.BaseEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.Set;

@Entity
@Table(name = "shared_users")
@Getter
@Setter
public class User extends BaseEntity {

    @Column(unique = true, nullable = false, length = 20)
    private String mobile;

    @Column(unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "is_verified", nullable = false)
    private Boolean isVerified = false;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "shared_user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles;
}