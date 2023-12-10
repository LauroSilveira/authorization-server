package com.lauro.authorization.server.dto;

import java.util.List;

public record UserDto(String username, String password, List<String> roles) {
}
