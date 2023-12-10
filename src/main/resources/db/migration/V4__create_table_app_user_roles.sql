-- Table app_user_roles JOIN of foreign key of user_id and role_id

CREATE TABLE app_user_roles (
  app_user_id BIGINT NOT NULL,
   role_id BIGINT NOT NULL,
   CONSTRAINT pk_app_user_roles PRIMARY KEY (app_user_id, role_id)
);

ALTER TABLE app_user_roles ADD CONSTRAINT fk_appuserol_on_app_user FOREIGN KEY (app_user_id) REFERENCES app_user (id);

ALTER TABLE app_user_roles ADD CONSTRAINT fk_appuserol_on_role FOREIGN KEY (role_id) REFERENCES role (id);