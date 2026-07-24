CREATE TABLE IF NOT EXISTS auth_events (
    event_id TEXT PRIMARY KEY,
    event_time TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT,
    event_type TEXT NOT NULL,
    success INTEGER CHECK (success IN (0, 1) OR success IS NULL),
    process_id INTEGER,
    raw_message TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS network_events (
    event_id TEXT PRIMARY KEY,
    event_time TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL CHECK (source_port BETWEEN 1 AND 65535),
    destination_port INTEGER NOT NULL CHECK (destination_port BETWEEN 1 AND 65535),
    tcp_flags TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    sensor_name TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS ip_profiles (
    source_ip TEXT PRIMARY KEY,
    ip_category TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    failed_count_total INTEGER NOT NULL DEFAULT 0,
    successful_count_total INTEGER NOT NULL DEFAULT 0,
    last_success_at TEXT,
    detection_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    current_block_status TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    failed_count INTEGER NOT NULL,
    successful_count INTEGER NOT NULL,
    invalid_user_count INTEGER NOT NULL,
    unique_username_count INTEGER NOT NULL,
    network_event_count INTEGER NOT NULL,
    attempt_rate REAL NOT NULL,
    recent_success INTEGER NOT NULL DEFAULT 0 CHECK (recent_success IN (0, 1)),
    previous_detection_count INTEGER NOT NULL DEFAULT 0,
    previous_block_count INTEGER NOT NULL DEFAULT 0,
    allowlisted INTEGER NOT NULL DEFAULT 0 CHECK (allowlisted IN (0, 1)),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_breakdown TEXT NOT NULL DEFAULT '{}',
    classification TEXT NOT NULL,
    decision TEXT NOT NULL,
    decision_reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    evidence_fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS detection_auth_events (
    detection_id TEXT NOT NULL,
    auth_event_id TEXT NOT NULL,
    PRIMARY KEY (detection_id, auth_event_id),
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE,
    FOREIGN KEY (auth_event_id) REFERENCES auth_events(event_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detection_network_events (
    detection_id TEXT NOT NULL,
    network_event_id TEXT NOT NULL,
    PRIMARY KEY (detection_id, network_event_id),
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE,
    FOREIGN KEY (network_event_id) REFERENCES network_events(event_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS allowlist (
    allowlist_id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    description TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_by TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS blocks (
    block_id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    removed_at TEXT,
    status TEXT NOT NULL,
    removal_method TEXT,
    firewall_result TEXT,
    error_message TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

CREATE TABLE IF NOT EXISTS action_requests (
    request_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    block_id TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    requested_reason TEXT NOT NULL,
    status TEXT NOT NULL,
    processed_at TEXT,
    result_message TEXT,
    FOREIGN KEY (block_id) REFERENCES blocks(block_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id TEXT PRIMARY KEY,
    event_time TEXT NOT NULL,
    component TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS parser_errors (
    error_id TEXT PRIMARY KEY,
    event_time TEXT NOT NULL,
    sensor TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    error_message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS component_health (
    component TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    last_success TEXT,
    last_error TEXT,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_auth_events_source_ip
    ON auth_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_auth_events_event_time
    ON auth_events(event_time);
CREATE INDEX IF NOT EXISTS idx_auth_events_source_time
    ON auth_events(source_ip, event_time);
CREATE INDEX IF NOT EXISTS idx_network_events_source_ip
    ON network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_event_time
    ON network_events(event_time);
CREATE INDEX IF NOT EXISTS idx_network_events_source_time
    ON network_events(source_ip, event_time);
CREATE INDEX IF NOT EXISTS idx_detections_source_ip
    ON detections(source_ip);
CREATE INDEX IF NOT EXISTS idx_detections_created_at
    ON detections(created_at);
CREATE INDEX IF NOT EXISTS idx_blocks_status
    ON blocks(status);
CREATE INDEX IF NOT EXISTS idx_blocks_expires_at
    ON blocks(expires_at);
CREATE INDEX IF NOT EXISTS idx_action_requests_status
    ON action_requests(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_time
    ON audit_log(event_time);
CREATE INDEX IF NOT EXISTS idx_allowlist_ip_active
    ON allowlist(ip_address, active);
