-- ReconForge database schema (generated from reconforge/db/models.py)
-- SQLite dialect shown; the same models create the PostgreSQL schema via SQLAlchemy.

CREATE TABLE notification_log (
	id INTEGER NOT NULL, 
	scan_id VARCHAR(32), 
	channel VARCHAR(32) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	fingerprints JSON NOT NULL, 
	change_ids JSON NOT NULL, 
	sent_at DATETIME NOT NULL, 
	error TEXT, 
	preview TEXT, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_notification_log_scan_id ON notification_log (scan_id);

CREATE TABLE schedules (
	id VARCHAR(32) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	target_name VARCHAR(200) NOT NULL, 
	frequency VARCHAR(16) NOT NULL, 
	cron VARCHAR(64) NOT NULL, 
	profile VARCHAR(64) NOT NULL, 
	incremental BOOLEAN NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	next_run_at DATETIME, 
	last_run_at DATETIME, 
	last_scan_id VARCHAR(32), 
	last_status VARCHAR(32), 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);


CREATE TABLE targets (
	id VARCHAR(32) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	config JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);


CREATE TABLE assets (
	id VARCHAR(32) NOT NULL, 
	target_id VARCHAR(32) NOT NULL, 
	type VARCHAR(32) NOT NULL, 
	"key" VARCHAR(1024) NOT NULL, 
	display VARCHAR(1024) NOT NULL, 
	scope VARCHAR(32) NOT NULL, 
	attributes JSON NOT NULL, 
	sources JSON NOT NULL, 
	confidence FLOAT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	first_scan_id VARCHAR(32), 
	last_scan_id VARCHAR(32), 
	false_positive BOOLEAN NOT NULL, 
	fp_reason TEXT, 
	tags JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_asset_identity UNIQUE (target_id, type, "key"), 
	FOREIGN KEY(target_id) REFERENCES targets (id)
);

CREATE INDEX ix_assets_target_id ON assets (target_id);
CREATE INDEX ix_asset_type ON assets (target_id, type);

CREATE TABLE scans (
	id VARCHAR(32) NOT NULL, 
	target_id VARCHAR(32) NOT NULL, 
	profile VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	"trigger" VARCHAR(32) NOT NULL, 
	incremental BOOLEAN NOT NULL, 
	started_at DATETIME NOT NULL, 
	finished_at DATETIME, 
	prev_scan_id VARCHAR(32), 
	modules_planned JSON NOT NULL, 
	modules_completed JSON NOT NULL, 
	modules_failed JSON NOT NULL, 
	modules_skipped JSON NOT NULL, 
	tools_executed JSON NOT NULL, 
	results_count INTEGER NOT NULL, 
	report_dir TEXT, 
	log_path TEXT, 
	error TEXT, 
	summary JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(target_id) REFERENCES targets (id)
);

CREATE INDEX ix_scans_target_id ON scans (target_id);

CREATE TABLE ai_analyses (
	id VARCHAR(32) NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	provider VARCHAR(64) NOT NULL, 
	model VARCHAR(64) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	result JSON NOT NULL, 
	rejected JSON NOT NULL, 
	error TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_ai_analyses_scan_id ON ai_analyses (scan_id);

CREATE TABLE asset_scores (
	id INTEGER NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	asset_id VARCHAR(32) NOT NULL, 
	score FLOAT NOT NULL, 
	tier VARCHAR(16) NOT NULL, 
	factors JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_asset_score UNIQUE (scan_id, asset_id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

CREATE INDEX ix_asset_scores_asset_id ON asset_scores (asset_id);
CREATE INDEX ix_asset_scores_scan_id ON asset_scores (scan_id);

CREATE TABLE asset_states (
	id INTEGER NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	asset_id VARCHAR(32) NOT NULL, 
	state_hash VARCHAR(32) NOT NULL, 
	state JSON NOT NULL, 
	modules JSON NOT NULL, 
	carried BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_asset_state UNIQUE (scan_id, asset_id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

CREATE INDEX ix_asset_states_scan_id ON asset_states (scan_id);
CREATE INDEX ix_asset_states_asset_id ON asset_states (asset_id);

CREATE TABLE changes (
	id VARCHAR(32) NOT NULL, 
	target_id VARCHAR(32) NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	prev_scan_id VARCHAR(32), 
	asset_id VARCHAR(32), 
	asset_type VARCHAR(32) NOT NULL, 
	asset_display VARCHAR(1024) NOT NULL, 
	category VARCHAR(64) NOT NULL, 
	significance VARCHAR(16) NOT NULL, 
	summary TEXT NOT NULL, 
	previous JSON, 
	current JSON, 
	first_observed DATETIME NOT NULL, 
	evidence_id VARCHAR(32), 
	fingerprint VARCHAR(32) NOT NULL, 
	notified BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(target_id) REFERENCES targets (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_changes_asset_id ON changes (asset_id);
CREATE INDEX ix_changes_target_id ON changes (target_id);
CREATE INDEX ix_changes_fingerprint ON changes (fingerprint);
CREATE INDEX ix_changes_scan_id ON changes (scan_id);

CREATE TABLE evidence (
	id VARCHAR(32) NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	module VARCHAR(64) NOT NULL, 
	kind VARCHAR(64) NOT NULL, 
	summary TEXT NOT NULL, 
	content TEXT, 
	path TEXT, 
	sha256 VARCHAR(64), 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_evidence_scan_id ON evidence (scan_id);

CREATE TABLE module_runs (
	id INTEGER NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	module VARCHAR(64) NOT NULL, 
	tool VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	started_at DATETIME, 
	finished_at DATETIME, 
	observations INTEGER NOT NULL, 
	inputs INTEGER NOT NULL, 
	skipped_inputs JSON NOT NULL, 
	command TEXT, 
	error TEXT, 
	skip_reason TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_module_runs_scan_id ON module_runs (scan_id);

CREATE TABLE observations (
	id VARCHAR(32) NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	asset_id VARCHAR(32) NOT NULL, 
	module VARCHAR(64) NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	observed_at DATETIME NOT NULL, 
	data JSON NOT NULL, 
	evidence_id VARCHAR(32), 
	confidence FLOAT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

CREATE INDEX ix_observations_evidence_id ON observations (evidence_id);
CREATE INDEX ix_observations_scan_id ON observations (scan_id);
CREATE INDEX ix_observations_asset_id ON observations (asset_id);

CREATE TABLE relations (
	id VARCHAR(32) NOT NULL, 
	target_id VARCHAR(32) NOT NULL, 
	src_id VARCHAR(32) NOT NULL, 
	dst_id VARCHAR(32) NOT NULL, 
	type VARCHAR(64) NOT NULL, 
	confirmed BOOLEAN NOT NULL, 
	confidence FLOAT NOT NULL, 
	attributes JSON NOT NULL, 
	sources JSON NOT NULL, 
	evidence_ids JSON NOT NULL, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	last_scan_id VARCHAR(32), 
	PRIMARY KEY (id), 
	CONSTRAINT uq_relation UNIQUE (src_id, dst_id, type), 
	FOREIGN KEY(target_id) REFERENCES targets (id), 
	FOREIGN KEY(src_id) REFERENCES assets (id) ON DELETE CASCADE, 
	FOREIGN KEY(dst_id) REFERENCES assets (id) ON DELETE CASCADE
);

CREATE INDEX ix_relations_target_id ON relations (target_id);
CREATE INDEX ix_relations_src_id ON relations (src_id);
CREATE INDEX ix_relations_dst_id ON relations (dst_id);

CREATE TABLE reports (
	id INTEGER NOT NULL, 
	scan_id VARCHAR(32) NOT NULL, 
	format VARCHAR(16) NOT NULL, 
	path TEXT NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_reports_scan_id ON reports (scan_id);

