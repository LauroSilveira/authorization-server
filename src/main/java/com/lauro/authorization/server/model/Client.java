package com.lauro.authorization.server.model;

import jakarta.persistence.*;
import lombok.*;
import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;


import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String clientId;
    private String clientSecret;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod> authenticationMethods;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;
    //private boolean requireProofKey;
    private String clientName;
    private boolean requireConsent;


    //Convert Client that Oauth will use
    public static RegisteredClient toRegisteredClient(final Client client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(am -> am.addAll(client.getAuthenticationMethods()))
                .authorizationGrantTypes( auth -> auth.addAll(client.getAuthorizationGrantTypes()))
                .redirectUris( uri -> uri.addAll(client.getRedirectUris()))
                .scopes(scope -> scope.addAll(client.getScopes()))
                .clientName(client.getClientName())
                .clientSettings(ClientSettings.builder()
                        //.requireProofKey(client.isRequireProofKey())
                        .requireAuthorizationConsent(client.isRequireConsent())
                        .build());

        return builder.build();

    }



}
