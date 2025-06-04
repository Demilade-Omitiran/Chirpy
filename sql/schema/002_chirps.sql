-- +goose Up
CREATE TABLE chirps(
  id UUID PRIMARY KEY DEFAULT GEN_RANDOM_UUID(),
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  body VARCHAR NOT NULL,
  user_id UUID NOT NULL,
  CONSTRAINT chirp_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES USERS(id)
    ON DELETE CASCADE
);

-- +goose Down
DROP TABLE chirps;