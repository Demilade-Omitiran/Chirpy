-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (created_at, updated_at, token, user_id, expires_at)
VALUES (
  NOW(), NOW(), $1, $2, $3
);