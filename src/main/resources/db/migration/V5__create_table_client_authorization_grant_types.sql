-- Table client_authorization_grant_types  JOIN of foreign key of client_id and authorization_grant_types
-- authorization_grant_types of Spring

CREATE TABLE client_authorization_grant_types (
  client_id BIGINT NOT NULL,
   authorization_grant_types BYTEA
);

ALTER TABLE client_authorization_grant_types ADD CONSTRAINT fk_client_authorizationgranttypes_on_client FOREIGN KEY (client_id) REFERENCES client (id);