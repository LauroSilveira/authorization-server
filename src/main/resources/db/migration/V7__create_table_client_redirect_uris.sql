-- Table client_redirect_uris  JOIN of foreign key of client_id and client_redirect_uris
-- client_redirect_uris of Spring

CREATE TABLE client_redirect_uris (
  client_id BIGINT NOT NULL,
   redirect_uris VARCHAR(255)
);

ALTER TABLE client_redirect_uris ADD CONSTRAINT fk_client_redirecturis_on_client FOREIGN KEY (client_id) REFERENCES client (id);