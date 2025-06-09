-- +goose Up
CREATE TABLE refresh_tokens(
  token TEXT PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  user_id UUID NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP,
  CONSTRAINT refresh_token_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES USERS(id)
    ON DELETE CASCADE
);

-- +goose Down
DROP TABLE refresh_tokens;