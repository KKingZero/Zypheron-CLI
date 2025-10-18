-- ============================================================================
-- ZYPHERON BLUE TEAM DEFENSE SYSTEM - DATABASE SCHEMA
-- Production-grade security threat tracking and AI defense management
-- ============================================================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search

-- ============================================================================
-- THREATS TABLE - Store all detected security threats
-- ============================================================================

CREATE TABLE IF NOT EXISTS threats (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  threat_id VARCHAR(255) UNIQUE NOT NULL,
  
  -- Threat Classification
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
  threat_type VARCHAR(50) NOT NULL CHECK (threat_type IN (
    'SQL_INJECTION', 
    'XSS', 
    'AUTH_BYPASS', 
    'BRUTE_FORCE', 
    'RATE_LIMIT', 
    'MALICIOUS_PAYLOAD',
    'PATH_TRAVERSAL',
    'CSRF',
    'XXE',
    'SSRF',
    'NONE'
  )),
  confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
  
  -- Threat Details
  description TEXT NOT NULL,
  affected_resources TEXT[] NOT NULL DEFAULT '{}',
  attack_vector TEXT NOT NULL,
  indicators TEXT[] NOT NULL DEFAULT '{}',
  
  -- AI Analysis
  ai_model VARCHAR(100) NOT NULL,
  recommended_action VARCHAR(20) NOT NULL CHECK (recommended_action IN ('BLOCK', 'MONITOR', 'ALERT', 'ALLOW')),
  auto_response BOOLEAN NOT NULL DEFAULT false,
  
  -- Request Details
  request_id VARCHAR(255),
  ip_address INET NOT NULL,
  user_agent TEXT,
  request_method VARCHAR(10),
  request_path TEXT NOT NULL,
  request_headers JSONB,
  request_body JSONB,
  request_params JSONB,
  request_query JSONB,
  
  -- User Information (if authenticated)
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  user_email VARCHAR(255),
  user_role VARCHAR(50),
  
  -- Timestamps
  detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  
  -- Indexing
  CONSTRAINT threats_threat_id_key UNIQUE (threat_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_threat_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_ip_address ON threats(ip_address);
CREATE INDEX IF NOT EXISTS idx_threats_user_id ON threats(user_id);
CREATE INDEX IF NOT EXISTS idx_threats_ai_model ON threats(ai_model);
CREATE INDEX IF NOT EXISTS idx_threats_request_path ON threats USING gin(request_path gin_trgm_ops);

-- ============================================================================
-- DEFENSE ACTIONS TABLE - Store automated defense responses
-- ============================================================================

CREATE TABLE IF NOT EXISTS defense_actions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  action_id VARCHAR(255) UNIQUE NOT NULL,
  threat_id VARCHAR(255) NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
  
  -- Action Details
  action_type VARCHAR(50) NOT NULL CHECK (action_type IN (
    'BLOCK_REQUEST',
    'RATE_LIMIT',
    'REQUIRE_MFA',
    'LOG_ONLY',
    'QUARANTINE',
    'PATCH_DEPLOY',
    'IP_BLOCK',
    'USER_SUSPEND',
    'ALERT_SENT'
  )),
  status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'EXECUTED', 'FAILED', 'CANCELLED')),
  
  -- Execution Details
  executed_by VARCHAR(20) NOT NULL CHECK (executed_by IN ('AI', 'HUMAN')),
  executed_at TIMESTAMP WITH TIME ZONE,
  ai_model VARCHAR(100),
  
  -- Results
  success BOOLEAN NOT NULL DEFAULT false,
  details TEXT NOT NULL,
  prevented_damage TEXT,
  error_message TEXT,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_defense_actions_threat_id ON defense_actions(threat_id);
CREATE INDEX IF NOT EXISTS idx_defense_actions_status ON defense_actions(status);
CREATE INDEX IF NOT EXISTS idx_defense_actions_executed_at ON defense_actions(executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_defense_actions_action_type ON defense_actions(action_type);

-- ============================================================================
-- ATTACK PATTERNS TABLE - Store identified attack patterns
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_patterns (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  pattern_id VARCHAR(255) UNIQUE NOT NULL,
  
  -- Pattern Details
  name VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  threat_level VARCHAR(20) NOT NULL CHECK (threat_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  
  -- Pattern Analysis
  frequency INTEGER NOT NULL DEFAULT 1,
  affected_endpoints TEXT[] NOT NULL DEFAULT '{}',
  attacker_fingerprint TEXT NOT NULL,
  mitigation_strategy TEXT NOT NULL,
  ai_confidence INTEGER NOT NULL CHECK (ai_confidence >= 0 AND ai_confidence <= 100),
  
  -- Related Threats
  related_threat_ids TEXT[] NOT NULL DEFAULT '{}',
  
  -- Timestamps
  first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
  last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_attack_patterns_threat_level ON attack_patterns(threat_level);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_first_seen ON attack_patterns(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_last_seen ON attack_patterns(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_frequency ON attack_patterns(frequency DESC);

-- ============================================================================
-- ATTACK PREDICTIONS TABLE - Store AI-generated attack predictions
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_predictions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  prediction_id VARCHAR(255) UNIQUE NOT NULL,
  
  -- Prediction Details
  predicted_threat_type VARCHAR(50) NOT NULL,
  probability INTEGER NOT NULL CHECK (probability >= 0 AND probability <= 100),
  estimated_time TIMESTAMP WITH TIME ZONE NOT NULL,
  reasoning TEXT NOT NULL,
  
  -- Preemptive Actions
  suggested_preemptive_actions TEXT[] NOT NULL DEFAULT '{}',
  actions_taken TEXT[] DEFAULT '{}',
  
  -- AI Model
  ai_model VARCHAR(100) NOT NULL,
  
  -- Validation (was the prediction correct?)
  validated BOOLEAN,
  actual_threat_id VARCHAR(255) REFERENCES threats(threat_id) ON DELETE SET NULL,
  validation_notes TEXT,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_attack_predictions_estimated_time ON attack_predictions(estimated_time);
CREATE INDEX IF NOT EXISTS idx_attack_predictions_probability ON attack_predictions(probability DESC);
CREATE INDEX IF NOT EXISTS idx_attack_predictions_validated ON attack_predictions(validated);

-- ============================================================================
-- SECURITY PATCHES TABLE - Store AI-generated security patches
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_patches (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  patch_id VARCHAR(255) UNIQUE NOT NULL,
  
  -- Vulnerability Details
  vuln_id VARCHAR(255) NOT NULL,
  vuln_type VARCHAR(100) NOT NULL,
  vuln_severity VARCHAR(20) NOT NULL CHECK (vuln_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  vuln_location TEXT NOT NULL,
  vuln_description TEXT NOT NULL,
  
  -- Patch Details
  patch_code TEXT NOT NULL,
  explanation TEXT NOT NULL,
  safety_score INTEGER NOT NULL CHECK (safety_score >= 0 AND safety_score <= 100),
  
  -- Testing & Deployment
  tested BOOLEAN NOT NULL DEFAULT false,
  test_results TEXT,
  deployed BOOLEAN NOT NULL DEFAULT false,
  deployment_status VARCHAR(20) CHECK (deployment_status IN ('PENDING', 'DEPLOYED', 'FAILED', 'ROLLED_BACK')),
  
  -- AI Model
  ai_model VARCHAR(100) NOT NULL,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deployed_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_security_patches_vuln_severity ON security_patches(vuln_severity);
CREATE INDEX IF NOT EXISTS idx_security_patches_deployed ON security_patches(deployed);
CREATE INDEX IF NOT EXISTS idx_security_patches_safety_score ON security_patches(safety_score DESC);

-- ============================================================================
-- DEFENSE CONFIGURATIONS TABLE - Store defense system configurations
-- ============================================================================

CREATE TABLE IF NOT EXISTS defense_configurations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  config_key VARCHAR(100) UNIQUE NOT NULL,
  config_value JSONB NOT NULL,
  description TEXT,
  
  -- Audit
  updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default configuration
INSERT INTO defense_configurations (config_key, config_value, description) VALUES
  ('threat_detection', '{"enabled": true, "aiEnabled": true, "autoBlock": false, "logAllRequests": false, "multiAIAnalysis": false}', 'Main threat detection settings'),
  ('rate_limits', '{"windowMs": 60000, "maxRequests": 100}', 'Rate limiting configuration'),
  ('whitelisted_ips', '{"ips": ["127.0.0.1", "::1"]}', 'Whitelisted IP addresses'),
  ('whitelisted_paths', '{"paths": ["/health", "/metrics", "/favicon.ico"]}', 'Whitelisted paths that bypass threat detection'),
  ('notification_channels', '{"email": true, "slack": false, "pagerduty": false}', 'Alert notification channels')
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================================
-- THREAT STATISTICS MATERIALIZED VIEW
-- For fast dashboard queries
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS threat_statistics AS
SELECT
  DATE_TRUNC('hour', detected_at) as hour,
  COUNT(*) as total_threats,
  COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical_count,
  COUNT(*) FILTER (WHERE severity = 'HIGH') as high_count,
  COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium_count,
  COUNT(*) FILTER (WHERE severity = 'LOW') as low_count,
  COUNT(DISTINCT ip_address) as unique_ips,
  AVG(confidence) as avg_confidence
FROM threats
WHERE detected_at > NOW() - INTERVAL '7 days'
GROUP BY hour
ORDER BY hour DESC;

-- Create index on materialized view
CREATE INDEX IF NOT EXISTS idx_threat_statistics_hour ON threat_statistics(hour DESC);

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_threats_updated_at BEFORE UPDATE ON threats
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_defense_actions_updated_at BEFORE UPDATE ON defense_actions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_attack_patterns_updated_at BEFORE UPDATE ON attack_patterns
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_attack_predictions_updated_at BEFORE UPDATE ON attack_predictions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_patches_updated_at BEFORE UPDATE ON security_patches
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to refresh threat statistics (call periodically)
CREATE OR REPLACE FUNCTION refresh_threat_statistics()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY threat_statistics;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE defense_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_predictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_patches ENABLE ROW LEVEL SECURITY;
ALTER TABLE defense_configurations ENABLE ROW LEVEL SECURITY;

-- Policies: Admins can see everything
CREATE POLICY "Admins can view all threats" ON threats
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM auth.users
      WHERE auth.users.id = auth.uid()
      AND auth.users.role IN ('admin', 'developer')
    )
  );

CREATE POLICY "Admins can view all defense actions" ON defense_actions
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM auth.users
      WHERE auth.users.id = auth.uid()
      AND auth.users.role IN ('admin', 'developer')
    )
  );

-- Users can only see their own threats
CREATE POLICY "Users can view their own threats" ON threats
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- ============================================================================
-- CLEANUP FUNCTION
-- Remove old data to prevent database bloat
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_defense_data()
RETURNS void AS $$
BEGIN
  -- Delete threats older than 90 days (NONE severity)
  DELETE FROM threats
  WHERE detected_at < NOW() - INTERVAL '90 days'
  AND severity = 'NONE';
  
  -- Delete non-critical threats older than 30 days
  DELETE FROM threats
  WHERE detected_at < NOW() - INTERVAL '30 days'
  AND severity IN ('LOW', 'MEDIUM');
  
  -- Keep CRITICAL and HIGH threats for 1 year
  DELETE FROM threats
  WHERE detected_at < NOW() - INTERVAL '1 year'
  AND severity IN ('CRITICAL', 'HIGH');
  
  -- Refresh statistics after cleanup
  PERFORM refresh_threat_statistics();
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

-- Grant access to authenticated users
GRANT SELECT ON threats TO authenticated;
GRANT SELECT ON defense_actions TO authenticated;
GRANT SELECT ON attack_patterns TO authenticated;
GRANT SELECT ON attack_predictions TO authenticated;
GRANT SELECT ON security_patches TO authenticated;
GRANT SELECT ON defense_configurations TO authenticated;
GRANT SELECT ON threat_statistics TO authenticated;

-- Grant insert/update to service role (for backend)
GRANT ALL ON threats TO service_role;
GRANT ALL ON defense_actions TO service_role;
GRANT ALL ON attack_patterns TO service_role;
GRANT ALL ON attack_predictions TO service_role;
GRANT ALL ON security_patches TO service_role;
GRANT ALL ON defense_configurations TO service_role;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE threats IS 'Stores all detected security threats with AI analysis';
COMMENT ON TABLE defense_actions IS 'Tracks automated and manual defense responses';
COMMENT ON TABLE attack_patterns IS 'Stores identified attack patterns across multiple threats';
COMMENT ON TABLE attack_predictions IS 'AI-generated predictions of future attacks';
COMMENT ON TABLE security_patches IS 'AI-generated security patches for vulnerabilities';
COMMENT ON TABLE defense_configurations IS 'System configuration for defense mechanisms';
COMMENT ON MATERIALIZED VIEW threat_statistics IS 'Aggregated threat statistics for dashboard';

-- ============================================================================
-- SETUP COMPLETE
-- ============================================================================

DO $$
BEGIN
  RAISE NOTICE '✅ Zypheron Blue Team Defense System - Database Schema Created Successfully';
  RAISE NOTICE '📊 Tables: threats, defense_actions, attack_patterns, attack_predictions, security_patches';
  RAISE NOTICE '🔒 Row Level Security: ENABLED';
  RAISE NOTICE '⚡ Indexes: CREATED for optimal query performance';
  RAISE NOTICE '🤖 Ready for AI-powered threat detection and defense!';
END $$;

