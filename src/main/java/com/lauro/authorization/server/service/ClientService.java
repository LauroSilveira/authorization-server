package com.lauro.authorization.server.service;

import com.lauro.authorization.server.dto.CreateClientDto;
import com.lauro.authorization.server.dto.MessageDto;
import com.lauro.authorization.server.exceptions.RoleException;
import com.lauro.authorization.server.model.Client;
import com.lauro.authorization.server.repository.ClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientService(ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = this.clientRepository.findByClientId(id)
                .orElseThrow(() -> new RoleException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = this.clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RoleException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    public MessageDto create(CreateClientDto dto) {
        Client client = this.clientFromDto(dto);
        this.clientRepository.save(client);
        return new MessageDto("Client saved");
    }

    private Client clientFromDto(CreateClientDto dto){
        return Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(this.passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requireConsent(dto.isRequireConsent())
                .clientName(dto.getClientName())
                .build();
    }
}
