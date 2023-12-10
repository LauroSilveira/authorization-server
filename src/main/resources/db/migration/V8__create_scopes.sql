-- Table client_scopes  JOIN of foreign key of client_id and client_scopes
-- client_scopes of Spring

CREATE TABLE client_scopes (
  client_id BIGINT NOT NULL,
   scopes VARCHAR(255)
);

ALTER TABLE client_scopes ADD CONSTRAINT fk_client_scopes_on_client FOREIGN KEY (client_id) REFERENCES client (id);