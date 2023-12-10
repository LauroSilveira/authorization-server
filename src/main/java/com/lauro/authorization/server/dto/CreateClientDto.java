package com.lauro.authorization.server.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

@Data
@NoArgsConstructor
public class CreateClientDto {
    //TODO: Refactor to Java Record
    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<ClientAuthenticationMethod> authenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
   // private boolean requireProofKey;
    private boolean requireConsent;
}
