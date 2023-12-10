package com.lauro.authorization.server.repository;

import com.lauro.authorization.server.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(final String username);

}
