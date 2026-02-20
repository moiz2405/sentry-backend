# ...existing code...
# This file is obsolete. The 'types' directory has been replaced by 'log_types'.

from enum import Enum


class Service(str, Enum):
    AUTH = "auth-service"
    API_GATEWAY = "api-gateway"
    USER = "user-service"
    PAYMENT = "payment-service"
    NOTIFICATION = "notification-service"
    INVENTORY = "inventory-service"
    # Add more based on registered services

class ErrorType(str, Enum):
    APPLICATION_EXCEPTION = "Application Exception"
    INFRASTRUCTURE_ERROR = "Infrastructure Error"
    NETWORK_ERROR = "Network Error"
    DATABASE_ERROR = "Database Error"
    SECURITY_ALERT = "Security Alert"
    RESOURCE_EXHAUSTION = "Resource Exhaustion"
    DEPLOYMENT_ISSUE = "Deployment Issue"
    TIMEOUT_ERROR = "Timeout"
    BUSINESS_LOGIC_ERROR = "Business Logic Error"
    PAYMENT_ERROR = "Payment Error"
    COMMUNICATION_ERROR = "Communication Error"
    UNKNOWN_ERROR = "Unknown"

class ErrorSubtype(str, Enum):
    STACK_TRACE = "Stack Trace"
    NULL_POINTER = "Null Pointer Exception"
    CONNECTION_REFUSED = "Connection Refused"
    TIMEOUT = "Timeout"
    OOM_KILLED = "Out of Memory (OOMKilled)"
    DB_CONN_FAILED = "Database Connection Failed"
    AUTH_FAILURE = "Authentication Failure"
    RATE_LIMIT_HIT = "Rate Limit Hit"
    CONFIG_MISMATCH = "Configuration Mismatch"
    SSL_HANDSHAKE_ERROR = "SSL Handshake Error"
    PERMISSION_DENIED = "Permission Denied"
    SERVICE_UNAVAILABLE = "Service Unavailable"
    CONFLICT = "Conflict"
    SUSPENSION = "Account Suspension"
    CHARGEBACK = "Chargeback"
    HTTP_4XX = "HTTP 4XX Error"
    HTTP_5XX = "HTTP 5XX Error"
    SMTP_ERROR = "SMTP Error"
    UNKNOWN = "Unknown"

class SeverityLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
