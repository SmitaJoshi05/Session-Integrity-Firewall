CREATE TABLE IF NOT EXISTS session_events (
  event_id      SERIAL PRIMARY KEY,
  session_id    UUID REFERENCES active_sessions(session_id) ON DELETE SET NULL,
  user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  event_type    VARCHAR(50) NOT NULL,
  risk_score    INTEGER DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk_level    VARCHAR(20) DEFAULT 'low'
                CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  action_taken  VARCHAR(50) NOT NULL,
  ip_hash       VARCHAR(255),
  ua_hash       VARCHAR(255),
  metadata      JSONB DEFAULT '{}',
  timestamp     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_session_events_session_id ON session_events(session_id);
CREATE INDEX idx_session_events_user_id    ON session_events(user_id);
CREATE INDEX idx_session_events_timestamp  ON session_events(timestamp DESC);
CREATE INDEX idx_session_events_risk_level ON session_events(risk_level);