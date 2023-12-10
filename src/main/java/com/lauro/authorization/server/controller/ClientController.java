package com.lauro.authorization.server.controller;

import com.lauro.authorization.server.dto.CreateClientDto;
import com.lauro.authorization.server.dto.MessageDto;
import com.lauro.authorization.server.service.ClientService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client")
public class ClientController {

    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    @PostMapping("/create")
    public ResponseEntity<MessageDto> create(@RequestBody final CreateClientDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.create(dto));
    }
}
