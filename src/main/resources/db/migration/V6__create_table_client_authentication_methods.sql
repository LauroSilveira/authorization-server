-- Table client_authentication_methods  JOIN of foreign key of client_id and client_authentication_methods
-- authorization_grant_types of Spring
CREATE TABLE client_authentication_methods (
  client_id BIGINT NOT NULL,
   authentication_methods BYTEA
);

ALTER TABLE client_authentication_methods ADD CONSTRAINT fk_client_authenticationmethods_on_client FOREIGN KEY (client_id) REFERENCES client (id);