export interface LoginResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  role: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface Flow {
  flow_id: string;
  session_id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status_code: number;
  request_size: number;
  response_size: number;
  content_type: string;
  timestamp: string;
}

export interface Session {
  session_id: string;
  client_ip: string;
  mac_address: string | null;
  user_agent: string | null;
  created_at: string;
  last_activity: string;
  request_count: number;
}

export interface Device {
  client_ip: string;
  mac_address: string | null;
  session_count: number;
  total_requests: number;
  last_seen: string;
  identifier: string;
}

export interface Finding {
  id: string;
  session_id: string;
  flow_id: string | null;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  recommendation: string | null;
  metadata: Record<string, any> | null;
}

export interface AnalysisStats {
  total_findings: number;
  by_severity: Record<string, number>;
  top_categories: Record<string, number>;
  orchestrator_metrics?: Record<string, any>;
}

export interface ProtocolAnalysis {
  flow_id: string;
  analyzers: Record<string, {
    analyzer_name: string;
    flow_id: string;
    session_id: string;
    findings: Finding[];
    metadata: Record<string, any>;
    timestamp: string;
  }>;
}

export interface ThreatIntel {
  domain: string;
  reputation: string;
  sources: string[];
  message?: string;
}

