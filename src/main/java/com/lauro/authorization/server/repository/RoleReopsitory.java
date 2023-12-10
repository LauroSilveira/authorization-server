package com.lauro.authorization.server.repository;

import com.lauro.authorization.server.model.Role;
import com.lauro.authorization.server.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleReopsitory extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(final RoleName roleName);
}
