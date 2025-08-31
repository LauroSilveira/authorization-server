package com.lauro.authorization.server.dto;

import com.lauro.authorization.server.model.Client;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;
import java.util.stream.Collectors;


public record CreateClientDTO(
        String clientId,
        String clientSecret,
        String clientName,
        Set<String> authenticationMethods,
        Set<String> authorizationGrantTypes,
        Set<String> redirectUris,
        Set<String> scopes,
        // private boolean requireProofKey,
        boolean requireConsent) {


    public Client clientFromDto(final PasswordEncoder passwordEncoder) {
        final var authenticationMethodSet = this.authenticationMethods()
                .stream()
                .map(ClientAuthenticationMethod::valueOf)
                .collect(Collectors.toSet());
        final var authorizationGrantTypeSet = this.authorizationGrantTypes()
                .stream()
                .map(a -> AuthorizationGrantType.CLIENT_CREDENTIALS)
                .collect(Collectors.toSet());
        return Client.builder()
                .clientId(this.clientId())
                .clientName(this.clientName())
                .clientSecret(passwordEncoder.encode(this.clientSecret()))
                .authenticationMethods(authenticationMethodSet)
                .authorizationGrantTypes(authorizationGrantTypeSet)
                .redirectUris(this.redirectUris())
                .scopes(this.scopes())
                .requireConsent(this.requireConsent())
                .build();
    }

}
