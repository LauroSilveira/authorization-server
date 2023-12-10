package com.lauro.authorization.server.exceptions;

public class RoleException extends RuntimeException{
    public RoleException() {
        super();
    }

    public RoleException(String message) {
        super(message);
    }
}
