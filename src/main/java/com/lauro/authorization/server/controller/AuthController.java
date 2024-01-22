package com.lauro.authorization.server.controller;

import com.lauro.authorization.server.dto.MessageDto;
import com.lauro.authorization.server.dto.UserDto;
import com.lauro.authorization.server.service.UserServiceImp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final UserServiceImp userServiceImpl;

    public AuthController(UserServiceImp userServiceImpl) {
        this.userServiceImpl = userServiceImpl;
    }

    @PostMapping("/create")
    public ResponseEntity<MessageDto> createUser(@RequestBody final UserDto dto) {
        log.info("[AuthController request to create new user: {}]", dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(userServiceImpl.createUser(dto));

    }
}
