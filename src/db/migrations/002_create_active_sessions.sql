CREATE TABLE IF NOT EXISTS active_sessions (
  session_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    VARCHAR(255) NOT NULL UNIQUE,
  ip_hash       VARCHAR(255) NOT NULL,
  ua_hash       VARCHAR(255) NOT NULL,
  device_hash   VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP DEFAULT NOW(),
  last_seen     TIMESTAMP DEFAULT NOW(),
  status        VARCHAR(20) DEFAULT 'active'
                CHECK (status IN ('active', 'terminated', 'blocked'))
);

CREATE INDEX idx_active_sessions_user_id  ON active_sessions(user_id);
CREATE INDEX idx_active_sessions_status   ON active_sessions(status);
CREATE INDEX idx_active_sessions_token    ON active_sessions(token_hash);