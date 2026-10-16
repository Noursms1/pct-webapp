-- PCT Unified Intelligence Layer
CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, source TEXT NOT NULL DEFAULT 'manual', source_url TEXT, category TEXT NOT NULL DEFAULT 'security', subcategory TEXT, languages TEXT NOT NULL DEFAULT '["*"]', frameworks TEXT, severity TEXT NOT NULL DEFAULT 'medium', cwe TEXT, owasp TEXT, cve TEXT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', pattern TEXT, ast_check TEXT, remediation TEXT, references_json TEXT, confidence REAL DEFAULT 1.0, enabled INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, version INTEGER DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_rules_languages ON rules(languages);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category, subcategory);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_cwe ON rules(cwe);
CREATE INDEX IF NOT EXISTS idx_rules_cve ON rules(cve);
CREATE INDEX IF NOT EXISTS idx_rules_source ON rules(source);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE TABLE IF NOT EXISTS rule_links (rule_a TEXT NOT NULL, rule_b TEXT NOT NULL, relation TEXT NOT NULL, weight REAL DEFAULT 1.0, PRIMARY KEY(rule_a,rule_b,relation));
CREATE TABLE IF NOT EXISTS package_rules (package TEXT NOT NULL, version_range TEXT NOT NULL DEFAULT '*', rule_id TEXT NOT NULL, relationship TEXT DEFAULT 'imports', PRIMARY KEY(package,version_range,rule_id));
CREATE TABLE IF NOT EXISTS correlations (id INTEGER PRIMARY KEY AUTOINCREMENT, unified_scan_id INTEGER, type TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT, evidence_json TEXT, recommendation TEXT, confidence REAL DEFAULT 0.8, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
