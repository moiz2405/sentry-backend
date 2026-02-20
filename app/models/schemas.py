"""
Pydantic models for LogViewer API
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

# Import existing enum types
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ..log_types.classifierTypes import SeverityLevel, ErrorType, ErrorSubtype, Service

class ServiceStatus(str, Enum):
    """Service health status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class LogLevel(str, Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"

class LogEntry(BaseModel):
    """Raw log entry from microservice"""
    service_name: str = Field(..., description="Name of the service sending the log")
    timestamp: datetime = Field(..., description="Timestamp of the log entry")
    level: LogLevel = Field(..., description="Log level")
    message: str = Field(..., description="Log message content")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Additional metadata")
    source_file: Optional[str] = Field(default=None, description="Source file name")
    line_number: Optional[int] = Field(default=None, description="Line number in source")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class LogBatch(BaseModel):
    """Batch of log entries"""
    service_name: str = Field(..., description="Name of the service")
    logs: List[LogEntry] = Field(..., description="List of log entries")
    batch_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('logs')
    def validate_logs_not_empty(cls, v):
        if not v:
            raise ValueError('Log batch cannot be empty')
        return v

class ProcessedLog(BaseModel):
    """Processed and classified log entry"""
    id: str = Field(..., description="Unique identifier for the log entry")
    original_log: LogEntry = Field(..., description="Original log entry")
    service: str = Field(..., description="Normalized service name")
    error_type: ErrorType = Field(..., description="Classified error type")
    error_sub_type: ErrorSubtype = Field(..., description="Classified error subtype")
    error_desc: str = Field(..., description="Human-readable error description")
    severity_level: SeverityLevel = Field(..., description="Severity level")
    timestamp: datetime = Field(..., description="Processing timestamp")
    is_anomaly: bool = Field(..., description="Whether this log is an anomaly")
    confidence_score: Optional[float] = Field(default=None, description="AI classification confidence")

class ServiceHealth(BaseModel):
    """Health status of a service"""
    service_name: str = Field(..., description="Name of the service")
    status: ServiceStatus = Field(..., description="Current health status")
    last_seen: datetime = Field(..., description="Last time logs were received")
    error_rate: float = Field(..., description="Error rate in the last interval")
    total_logs: int = Field(..., description="Total logs received")
    error_count: int = Field(..., description="Number of errors")
    warning_count: int = Field(..., description="Number of warnings")
    severity_breakdown: Dict[str, int] = Field(..., description="Breakdown by severity")
    most_common_errors: List[str] = Field(..., description="Most common error types")
    uptime_percentage: float = Field(..., description="Service uptime percentage")

class ProcessingStats(BaseModel):
    """Real-time processing statistics"""
    total_logs_processed: int = Field(..., description="Total logs processed")
    logs_per_second: float = Field(..., description="Current processing rate")
    active_services: int = Field(..., description="Number of active services")
    total_anomalies: int = Field(..., description="Total anomalies detected")
    processing_lag: float = Field(..., description="Processing lag in seconds")
    last_processed_timestamp: datetime = Field(..., description="Last processing timestamp")
    queue_size: int = Field(..., description="Current queue size")
    
class AlertRule(BaseModel):
    """Alert rule configuration"""
    id: Optional[str] = Field(default=None, description="Rule ID")
    name: str = Field(..., description="Rule name")
    service_name: str = Field(..., description="Target service name")
    condition: str = Field(..., description="Alert condition")
    threshold: float = Field(..., description="Alert threshold")
    severity: SeverityLevel = Field(..., description="Alert severity")
    enabled: bool = Field(default=True, description="Whether rule is enabled")
    
class Alert(BaseModel):
    """Generated alert"""
    id: str = Field(..., description="Alert ID")
    rule_id: str = Field(..., description="Rule that triggered the alert")
    service_name: str = Field(..., description="Affected service")
    message: str = Field(..., description="Alert message")
    severity: SeverityLevel = Field(..., description="Alert severity")
    timestamp: datetime = Field(..., description="Alert timestamp")
    resolved: bool = Field(default=False, description="Whether alert is resolved")
    
class ServiceRegistration(BaseModel):
    """Service registration request"""
    service_name: str = Field(..., description="Name of the service to register")
    description: Optional[str] = Field(default=None, description="Service description")
    log_format: Optional[str] = Field(default=None, description="Expected log format")
    health_check_url: Optional[str] = Field(default=None, description="Health check endpoint")
    notification_settings: Optional[Dict[str, Any]] = Field(default={}, description="Notification preferences")

class LogStreamResponse(BaseModel):
    """Response for log streaming endpoint"""
    message: str = Field(..., description="Response message")
    logs_received: int = Field(..., description="Number of logs received")
    processing_started: bool = Field(..., description="Whether processing started")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class HealthCheckResponse(BaseModel):
    """Health check response"""
    service: str = Field(..., description="Service name")
    status: ServiceStatus = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Check timestamp")
    details: Dict[str, Any] = Field(..., description="Additional health details")

class AnalyticsQuery(BaseModel):
    """Analytics query parameters"""
    service_name: Optional[str] = Field(default=None, description="Filter by service")
    start_time: Optional[datetime] = Field(default=None, description="Start time filter")
    end_time: Optional[datetime] = Field(default=None, description="End time filter")
    severity_levels: Optional[List[SeverityLevel]] = Field(default=None, description="Filter by severity")
    error_types: Optional[List[ErrorType]] = Field(default=None, description="Filter by error type")
    limit: int = Field(default=100, description="Maximum results to return")
    offset: int = Field(default=0, description="Results offset for pagination")

class AnalyticsResponse(BaseModel):
    """Analytics response"""
    total_count: int = Field(..., description="Total matching records")
    results: List[ProcessedLog] = Field(..., description="Query results")
    aggregations: Dict[str, Any] = Field(..., description="Aggregated statistics")
    query_time_ms: float = Field(..., description="Query execution time")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class SystemHealth(BaseModel):
    """Overall system health status"""
    overall_status: str = Field(..., description="Overall system health: healthy, warning, critical")
    services: List[ServiceHealth] = Field(..., description="Health status for all services")
    total_services: int = Field(..., description="Total number of services")
    healthy_services: int = Field(..., description="Number of healthy services")
    warning_services: int = Field(..., description="Number of services in warning state")
    critical_services: int = Field(..., description="Number of services in critical state")
    last_updated: datetime = Field(..., description="Last update timestamp")

class HealthAlert(BaseModel):
    """Health alert for a service or system"""
    id: str = Field(..., description="Alert ID")
    service_name: Optional[str] = Field(None, description="Service affected")
    message: str = Field(..., description="Alert message")
    severity: SeverityLevel = Field(..., description="Severity of the alert")
    status: str = Field(..., description="active, acknowledged, resolved")
    timestamp: datetime = Field(..., description="When the alert was triggered")
    acknowledged: bool = Field(default=False, description="Whether alert is acknowledged")
    dismissed: bool = Field(default=False, description="Whether alert is dismissed")

class HealthQuery(BaseModel):
    """Query for health data"""
    service_name: Optional[str] = Field(None, description="Service to filter")
    status_filter: Optional[List[str]] = Field(None, description="Filter by status: healthy, warning, critical")
    start_time: Optional[datetime] = Field(None, description="Start time for query")
    end_time: Optional[datetime] = Field(None, description="End time for query")

class HealthResponse(BaseModel):
    """Response for health query"""
    services: List[ServiceHealth] = Field(..., description="List of service health objects")
    total_count: int = Field(..., description="Total number of services returned")
    query_timestamp: datetime = Field(..., description="Query execution timestamp")
    filters_applied: Dict[str, Any] = Field(..., description="Filters used in the query")

class AlertConfiguration(BaseModel):
    """Configuration for alert thresholds and rules"""
    service_name: Optional[str] = Field(None, description="Service to configure")
    error_rate_threshold: Optional[float] = Field(None, description="Error rate threshold for alerts")
    latency_threshold: Optional[float] = Field(None, description="Latency threshold for alerts (ms)")
    downtime_threshold: Optional[float] = Field(None, description="Downtime threshold (seconds)")
    severity: Optional[SeverityLevel] = Field(None, description="Severity for triggered alerts")
    enabled: bool = Field(default=True, description="Whether alerting is enabled")
    custom_rules: Optional[List[AlertRule]] = Field(default=None, description="Custom alert rules")

class TrendAnalysis(BaseModel):
    """Trend analysis for a service or system"""
    service_name: Optional[str] = Field(None, description="Service name (if applicable)")
    time_range: Dict[str, datetime] = Field(..., description="Start and end time for the trend analysis")
    error_rate_trend: Dict[str, Any] = Field(..., description="Current, previous, change_percent, trend")
    volume_trend: Dict[str, Any] = Field(..., description="Current, previous, change_percent, trend")
    performance_trend: Dict[str, Any] = Field(..., description="Performance metrics trend")
    anomalies: Optional[list] = Field(default_factory=list, description="Detected anomalies")
    insights: Optional[list] = Field(default_factory=list, description="AI-generated insights")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Trend analysis timestamp")

class ServiceInsight(BaseModel):
    """AI-generated insight for a service"""
    service_name: str = Field(..., description="Service name")
    insight_type: str = Field(..., description="Type of insight, e.g. anomaly, optimization, risk")
    message: str = Field(..., description="Insight message or recommendation")
    severity: Optional[SeverityLevel] = Field(None, description="Severity of the insight")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Insight timestamp")
    details: Optional[dict] = Field(default_factory=dict, description="Additional insight details")

class ErrorPattern(BaseModel):
    """Recurring error pattern across logs/services"""
    pattern: str = Field(..., description="Error pattern or signature")
    count: int = Field(..., description="Number of occurrences")
    services: List[str] = Field(..., description="Services affected")
    first_seen: datetime = Field(..., description="First occurrence timestamp")
    last_seen: datetime = Field(..., description="Last occurrence timestamp")
    severity: Optional[SeverityLevel] = Field(None, description="Severity of the pattern")

class PerformanceMetrics(BaseModel):
    """Performance metrics for a service"""
    service_name: str = Field(..., description="Service name")
    time_range: Dict[str, datetime] = Field(..., description="Start and end time")
    response_times: Dict[str, float] = Field(..., description="Average, median, p95, p99, min, max")
    throughput: Dict[str, float] = Field(..., description="Requests per second, peak, total")
    error_rates: Dict[str, Any] = Field(..., description="Error rates by type and overall")
    availability: Dict[str, Any] = Field(..., description="Uptime, downtime, incidents")
    resource_usage: Dict[str, float] = Field(..., description="CPU, memory, disk, network usage")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Metrics timestamp")

class AlertInsight(BaseModel):
    """Insight about alerting patterns and effectiveness"""
    alert_id: Optional[str] = Field(None, description="Alert ID if applicable")
    service_name: Optional[str] = Field(None, description="Service name")
    insight_type: str = Field(..., description="Type of insight, e.g. false positive, delayed response")
    message: str = Field(..., description="Insight message")
    severity: Optional[SeverityLevel] = Field(None, description="Severity of the insight")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Insight timestamp")
    details: Optional[dict] = Field(default_factory=dict, description="Additional details")

class LogDistribution(BaseModel):
    """Log volume distribution over time and by service/severity"""
    time_range: Dict[str, datetime] = Field(..., description="Start and end time")
    granularity: str = Field(..., description="minute, hour, day")
    distribution_by_service: Dict[str, int] = Field(..., description="Log count per service")
    distribution_by_severity: Dict[str, int] = Field(..., description="Log count per severity")
    time_series: List[Dict[str, Any]] = Field(..., description="Time series data for plotting")
    total_logs: int = Field(..., description="Total logs in range")
    peak_volume: int = Field(..., description="Peak log volume in a period")
    average_volume: float = Field(..., description="Average log volume per period")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Distribution timestamp")

class NotificationCreate(BaseModel):
    """Create a new notification"""
    title: str = Field(..., description="Notification title")
    message: str = Field(..., description="Notification message")
    severity: SeverityLevel = Field(..., description="Severity of the notification")
    service_name: Optional[str] = Field(None, description="Target service name")
    channels: List[str] = Field(..., description="Channels to send notification (email, slack, webhook)")
    metadata: Optional[dict] = Field(default_factory=dict, description="Additional metadata")

class NotificationResponse(BaseModel):
    """Notification response object"""
    id: str = Field(..., description="Notification ID")
    title: str = Field(..., description="Notification title")
    message: str = Field(..., description="Notification message")
    severity: SeverityLevel = Field(..., description="Severity of the notification")
    service_name: Optional[str] = Field(None, description="Target service name")
    channels: List[str] = Field(..., description="Channels notification sent to")
    status: str = Field(..., description="Notification status (pending, sent, failed)")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    metadata: Optional[dict] = Field(default_factory=dict, description="Additional metadata")

class NotificationUpdate(BaseModel):
    """Update notification fields"""
    title: Optional[str] = Field(None, description="Notification title")
    message: Optional[str] = Field(None, description="Notification message")
    severity: Optional[SeverityLevel] = Field(None, description="Severity")
    status: Optional[str] = Field(None, description="Status")
    channels: Optional[List[str]] = Field(None, description="Channels")
    metadata: Optional[dict] = Field(default_factory=dict, description="Additional metadata")

class NotificationPreferences(BaseModel):
    """User or system notification preferences"""
    email_enabled: bool = Field(default=True)
    slack_enabled: bool = Field(default=False)
    webhook_enabled: bool = Field(default=False)
    severity_threshold: str = Field(default="warning")
    quiet_hours: dict = Field(default_factory=lambda: {"enabled": False, "start_time": "22:00", "end_time": "08:00", "timezone": "UTC"})
    rate_limiting: dict = Field(default_factory=lambda: {"enabled": True, "max_per_hour": 10, "max_per_day": 100})
    service_filters: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class NotificationChannel(BaseModel):
    """Notification channel configuration"""
    id: str = Field(..., description="Channel ID")
    type: str = Field(..., description="Channel type (email, slack, webhook)")
    name: str = Field(..., description="Channel name")
    configuration: dict = Field(..., description="Channel configuration details")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class NotificationRule(BaseModel):
    """Notification rule for triggering notifications"""
    id: Optional[str] = Field(None, description="Rule ID")
    name: str = Field(..., description="Rule name")
    service_name: Optional[str] = Field(None, description="Target service")
    condition: str = Field(..., description="Trigger condition")
    severity: SeverityLevel = Field(..., description="Severity for triggered notifications")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class BulkNotificationAction(BaseModel):
    """Bulk action on notifications"""
    action: str = Field(..., description="Action to perform (acknowledge, delete, mark_read)")
    notification_ids: List[str] = Field(..., description="List of notification IDs")

class WebSocketMessage(BaseModel):
    """Generic WebSocket message structure"""
    type: str = Field(..., description="Message type, e.g. ping, subscribe, update")
    data: Optional[dict] = Field(default_factory=dict, description="Payload data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Message timestamp")

class WebSocketResponse(BaseModel):
    """WebSocket response message"""
    type: str = Field(..., description="Response type")
    data: Optional[dict] = Field(default_factory=dict, description="Response data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

class SubscriptionRequest(BaseModel):
    """WebSocket subscription request"""
    subscription_type: str = Field(..., description="Type of subscription, e.g. service_logs, health")
    service_name: Optional[str] = Field(None, description="Service to subscribe to")
    filters: Optional[dict] = Field(default_factory=dict, description="Subscription filters")

class WebSocketConnectionInfo(BaseModel):
    """Information about a WebSocket connection"""
    client_id: str = Field(..., description="Client identifier")
    service_filter: Optional[str] = Field(None, description="Service filter for the connection")
    connection_type: Optional[str] = Field(None, description="Type of connection, e.g. logs, health")
    connected_at: datetime = Field(..., description="Connection start time")
    last_activity: datetime = Field(..., description="Last activity timestamp")
