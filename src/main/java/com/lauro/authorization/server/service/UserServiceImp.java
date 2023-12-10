package com.lauro.authorization.server.service;

import com.lauro.authorization.server.dto.MessageDto;
import com.lauro.authorization.server.dto.UserDto;
import com.lauro.authorization.server.exceptions.RoleException;
import com.lauro.authorization.server.model.AppUser;
import com.lauro.authorization.server.model.Role;
import com.lauro.authorization.server.model.RoleName;
import com.lauro.authorization.server.repository.RoleReopsitory;
import com.lauro.authorization.server.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@Slf4j
public class UserServiceImp {

    private final UserRepository userRepository;
    private final RoleReopsitory roleReopsitory;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImp(UserRepository userRepository, RoleReopsitory roleReopsitory,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleReopsitory = roleReopsitory;
        this.passwordEncoder = passwordEncoder;
    }

    public MessageDto createUser(final UserDto dto) {
        Set<Role> roles = new HashSet<>();
        final var newUser = AppUser.builder()
                .username(dto.username())
                .password(this.passwordEncoder.encode(dto.password()))
                .build();

        dto.roles().forEach(r -> {
            final Role roleFound = this.roleReopsitory.findByRoleName(RoleName.valueOf(r))
                    .orElseThrow(() -> new RoleException("Role not found"));
            roles.add(roleFound);
        });
        newUser.setRoles(roles);
        this.userRepository.save(newUser);
        return new MessageDto("Created new AppUser: " + dto);
    }
}
