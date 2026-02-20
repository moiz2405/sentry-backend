import json
import logging
import time
from typing import List, Dict, Tuple, Optional
from pydantic import BaseModel, Field
from agno.agent import Agent
from agno.models.groq import Groq

# from backend.app.types.classifierTypes import SeverityLevel  # Types already defined elsewhere
from ..log_types.classifierTypes import SeverityLevel, ErrorType, ErrorSubtype, Service

# Configure logging
logging.basicConfig(level=logging.INFO)

# --------------------------------------------
# Classification Normalization
# --------------------------------------------

# Error type mappings for consistent classification
ERROR_TYPES: Dict[str, Tuple[str, str]] = {
    "nullpointer": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.NULL_POINTER.value),
    "timeout": (ErrorType.TIMEOUT_ERROR.value, ErrorSubtype.TIMEOUT.value),
    "connection": (ErrorType.NETWORK_ERROR.value, ErrorSubtype.CONNECTION_REFUSED.value),
    "database": (ErrorType.DATABASE_ERROR.value, ErrorSubtype.DB_CONN_FAILED.value),
    "authentication": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.AUTH_FAILURE.value),
    "authorization": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.PERMISSION_DENIED.value),
    "outofmemory": (ErrorType.RESOURCE_EXHAUSTION.value, ErrorSubtype.OOM_KILLED.value),
    "stacktrace": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.STACK_TRACE.value),
    "filenotfound": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.UNKNOWN.value),
    "ioexception": (ErrorType.INFRASTRUCTURE_ERROR.value, ErrorSubtype.UNKNOWN.value),
    "sql": (ErrorType.DATABASE_ERROR.value, ErrorSubtype.DB_CONN_FAILED.value),
    "json": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.UNKNOWN.value),
    "validation": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.UNKNOWN.value),
    "http": (ErrorType.NETWORK_ERROR.value, ErrorSubtype.UNKNOWN.value),
    "ssl": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.SSL_HANDSHAKE_ERROR.value),
    "certificate": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.SSL_HANDSHAKE_ERROR.value),
    "permission": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.PERMISSION_DENIED.value),
    "quota": (ErrorType.RESOURCE_EXHAUSTION.value, ErrorSubtype.RATE_LIMIT_HIT.value),
    "rate": (ErrorType.RESOURCE_EXHAUSTION.value, ErrorSubtype.RATE_LIMIT_HIT.value),
    "circuit": (ErrorType.INFRASTRUCTURE_ERROR.value, ErrorSubtype.SERVICE_UNAVAILABLE.value),
    "conflict": (ErrorType.BUSINESS_LOGIC_ERROR.value, ErrorSubtype.CONFLICT.value),
    "suspension": (ErrorType.PAYMENT_ERROR.value, ErrorSubtype.SUSPENSION.value),
    "suspended": (ErrorType.PAYMENT_ERROR.value, ErrorSubtype.SUSPENSION.value),
    "chargeback": (ErrorType.PAYMENT_ERROR.value, ErrorSubtype.CHARGEBACK.value),
    "smtp": (ErrorType.COMMUNICATION_ERROR.value, ErrorSubtype.SMTP_ERROR.value),
    "mail": (ErrorType.COMMUNICATION_ERROR.value, ErrorSubtype.SMTP_ERROR.value),
    "503": (ErrorType.INFRASTRUCTURE_ERROR.value, ErrorSubtype.HTTP_5XX.value),
    "502": (ErrorType.INFRASTRUCTURE_ERROR.value, ErrorSubtype.HTTP_5XX.value),
    "500": (ErrorType.INFRASTRUCTURE_ERROR.value, ErrorSubtype.HTTP_5XX.value),
    "409": (ErrorType.BUSINESS_LOGIC_ERROR.value, ErrorSubtype.CONFLICT.value),
    "404": (ErrorType.APPLICATION_EXCEPTION.value, ErrorSubtype.HTTP_4XX.value),
    "401": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.AUTH_FAILURE.value),
    "403": (ErrorType.SECURITY_ALERT.value, ErrorSubtype.PERMISSION_DENIED.value),
}

# Service name mappings for consistent naming
SERVICE_MAPPINGS: Dict[str, str] = {
    "auth": Service.AUTH.value,
    "user": Service.USER.value, 
    "payment": Service.PAYMENT.value,
    "order": "order-service",  # Not in enum, keeping as string
    "inventory": Service.INVENTORY.value,
    "notification": Service.NOTIFICATION.value,
    "gateway": Service.API_GATEWAY.value,
    "database": "database-service",  # Not in enum, keeping as string
    "cache": "cache-service",  # Not in enum, keeping as string
    "mail": "mail-service",  # Not in enum, keeping as string
}

def normalize_classification(error_desc: str, service: str) -> Tuple[ErrorType, ErrorSubtype, str]:
    """
    Normalize error classification using predefined mappings.
    Returns (error_type, error_sub_type, normalized_service)
    """
    error_desc_lower = error_desc.lower()
    
    # Find matching error type using enum defaults
    error_type = ErrorType.UNKNOWN_ERROR
    error_sub_type = ErrorSubtype.UNKNOWN
    
    for keyword, (e_type_str, e_sub_type_str) in ERROR_TYPES.items():
        if keyword in error_desc_lower:
            # Convert string values back to enums
            for et in ErrorType:
                if et.value == e_type_str:
                    error_type = et
                    break
            for est in ErrorSubtype:
                if est.value == e_sub_type_str:
                    error_sub_type = est
                    break
            break
    
    # Normalize service name
    service_lower = service.lower()
    normalized_service = service
    for keyword, mapped_service in SERVICE_MAPPINGS.items():
        if keyword in service_lower:
            normalized_service = mapped_service
            break
    
    return error_type, error_sub_type, normalized_service

def normalize_severity(severity_str: str) -> SeverityLevel:
    """
    Normalize severity string to proper enum value.
    """
    severity_lower = severity_str.lower()
    if severity_lower in ["high", "critical", "fatal", "emergency"]:
        return SeverityLevel.HIGH
    elif severity_lower in ["low", "info", "debug", "warning"]:
        return SeverityLevel.LOW
    else:
        return SeverityLevel.MEDIUM

# --------------------------------------------
# Response Schema
# --------------------------------------------

class LogsClassifier(BaseModel):
    service: str = Field(..., description="Microservice name like auth-service, payment-service etc.")
    error_type: ErrorType = Field(..., description="General category like Application Exception, Database Error, etc.")
    error_sub_type: ErrorSubtype = Field(..., description="Specific kind like Timeout, Stack Trace, etc.")
    error_desc: str = Field(..., description="Concise human-readable error excerpt.")
    severity_level: SeverityLevel = Field(..., description="How urgent or severe: Low, Medium, High.")
    timestamp: Optional[str] = Field(None, description="Timestamp when the error occurred.")

class FallbackClassification:
    @staticmethod
    def create_fallback(log_data: dict, timestamp: Optional[str] = None) -> LogsClassifier:
        """Create a fallback classification when LLM API fails."""
        # Extract basic info from log data
        line = log_data.get("line", "") if isinstance(log_data, dict) else str(log_data)
        compact_error = log_data.get("compact_error", line) if isinstance(log_data, dict) else line
        
        # Use normalization to get basic classification
        error_type, error_sub_type, service = normalize_classification(compact_error, "unknown-service")
        
        # Determine severity based on keywords using proper enum values
        severity = SeverityLevel.MEDIUM  # Default
        if any(keyword in compact_error.lower() for keyword in ["fatal", "critical", "emergency"]):
            severity = SeverityLevel.HIGH
        elif any(keyword in compact_error.lower() for keyword in ["warning", "info", "debug"]):
            severity = SeverityLevel.LOW
        
        return LogsClassifier(
            service=service,
            error_type=error_type,
            error_sub_type=error_sub_type,
            error_desc=compact_error[:200] + "..." if len(compact_error) > 200 else compact_error,
            severity_level=severity,
            timestamp=timestamp
        )

# --------------------------------------------
# Agent Setup
# --------------------------------------------

def get_agent() -> Agent:
    return Agent(
        model=Groq(id="llama-3.3-70b-versatile"),
        description=(
            "You are a log classifier.\n"
            "From each log entry, extract the following fields:\n"
            "- `service`: (e.g., auth-service, user-service, payment-service)\n"
            "- `error_type`: (Application Exception, Infrastructure Error, Network Error, etc.)\n"
            "- `error_sub_type`: (Null Pointer Exception, Timeout, Stack Trace, etc.)\n"
            "- `error_desc`: A concise description (e.g., 'NullPointerException in UserController.java')\n"
            "- `severity_level`: One of Low, Medium, or High\n"
        ),
        markdown=True,
        response_model=LogsClassifier,
    )

AGENT_MAIN = get_agent()

# --------------------------------------------
# Agent Management for Performance Optimization
# --------------------------------------------

class AgentManager:
    """Manages agent instances for optimal performance in batch operations."""
    
    def __init__(self):
        self._agent = None
    
    def get_agent(self) -> Agent:
        """Get or create agent instance (singleton pattern for performance)."""
        if self._agent is None:
            self._agent = get_agent()
            logging.info("Initialized new agent instance")
        return self._agent
    
    def reset_agent(self):
        """Reset agent instance (useful for error recovery)."""
        self._agent = None
        logging.info("Agent instance reset")

# Global agent manager instance
AGENT_MANAGER = AgentManager()

def get_preloaded_agent() -> Agent:
    """Get a preloaded agent for performance optimization."""
    return AGENT_MANAGER.get_agent()

# --------------------------------------------
# Core Classification Logic
# --------------------------------------------

def classify_log_with_retry(log_data: dict, max_retries: int = 3, agent: Optional[Agent] = None) -> LogsClassifier:
    """
    Classify a log entry with retry logic and fallback handling.
    Accepts log data with timestamp and other metadata.
    
    Args:
        log_data: Log entry data (dict with metadata or string)
        max_retries: Maximum number of retry attempts
        agent: Optional pre-initialized agent for performance optimization
    """
    # Use provided agent or fall back to global instance
    classifier_agent = agent or AGENT_MAIN
    
    # Extract timestamp if available
    timestamp = log_data.get("timestamp") if isinstance(log_data, dict) else None
    log_line = log_data.get("line", str(log_data)) if isinstance(log_data, dict) else str(log_data)
    
    for attempt in range(max_retries):
        try:
            prompt = f"Classify this log into structured fields:\n{log_line}"
            response = classifier_agent.run(prompt, stream=False)
            
            # Get the classification result
            result = response.content
            
            # If result is a string, try to parse it as JSON or fallback
            if isinstance(result, str):
                try:
                    # Try to parse as dict
                    import json as _json
                    result_dict = _json.loads(result)
                    
                    # Convert string values to proper enum types
                    if "error_type" in result_dict and isinstance(result_dict["error_type"], str):
                        # Find matching enum value
                        for error_type_enum in ErrorType:
                            if error_type_enum.value == result_dict["error_type"]:
                                result_dict["error_type"] = error_type_enum
                                break
                        else:
                            result_dict["error_type"] = ErrorType.UNKNOWN_ERROR
                    
                    if "error_sub_type" in result_dict and isinstance(result_dict["error_sub_type"], str):
                        # Find matching enum value
                        for error_sub_type_enum in ErrorSubtype:
                            if error_sub_type_enum.value == result_dict["error_sub_type"]:
                                result_dict["error_sub_type"] = error_sub_type_enum
                                break
                        else:
                            result_dict["error_sub_type"] = ErrorSubtype.UNKNOWN
                    
                    # If severity_level is a string, normalize it
                    if "severity_level" in result_dict and isinstance(result_dict["severity_level"], str):
                        result_dict["severity_level"] = normalize_severity(result_dict["severity_level"])
                    
                    # Add timestamp if missing
                    if timestamp:
                        result_dict["timestamp"] = timestamp
                    
                    result = LogsClassifier(**result_dict)
                except Exception as parse_exc:
                    logging.warning(f"Could not parse LLM string result: {parse_exc}. Using fallback.")
                    return FallbackClassification.create_fallback(log_data, timestamp)
            else:
                # Add timestamp to the result (for Pydantic model objects)
                if timestamp and hasattr(result, 'timestamp'):
                    result.timestamp = timestamp
                elif timestamp:
                    # If the result doesn't have timestamp field, create new instance
                    result_dict = result.dict()
                    result_dict['timestamp'] = timestamp
                    result = LogsClassifier(**result_dict)
            
            # Apply normalization to ensure consistency
            error_type, error_sub_type, service = normalize_classification(
                result.error_desc, result.service
            )
            result.error_type = error_type
            result.error_sub_type = error_sub_type
            result.service = service
            
            # Normalize severity level to proper enum value
            if isinstance(result.severity_level, str):
                result.severity_level = normalize_severity(result.severity_level)
            
            logging.info(f"Successfully classified log on attempt {attempt + 1}")
            return result
            
        except Exception as e:
            logging.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logging.error(f"All {max_retries} attempts failed. Using fallback classification.")
                return FallbackClassification.create_fallback(log_data, timestamp)

def classify_log(log_line: str, agent: Optional[Agent] = None) -> LogsClassifier:
    """Legacy function for backward compatibility."""
    return classify_log_with_retry({"line": log_line}, agent=agent)

# --------------------------------------------
# Main Classification Handler
# --------------------------------------------

def classify_logs(input_path: str, output_path: str, agent: Optional[Agent] = None) -> List[LogsClassifier]:
    """
    Enhanced classification handler that supports both old and new metadata formats.
    
    Args:
        input_path: Path to input JSON file with log data
        output_path: Path to save classified results
        agent: Optional pre-initialized agent for performance optimization
    """
    # Initialize agent if not provided (for repeated calls optimization)
    if agent is None:
        agent = get_agent()
        logging.info("Initialized new agent for classification")
    else:
        logging.info("Using provided pre-initialized agent")
    
    results = []

    with open(input_path, "r") as f:
        log_data = json.load(f)

    total_logs = len(log_data)
    logging.info(f"Processing {total_logs} log entries...")

    for idx, (key, log_entry) in enumerate(log_data.items(), 1):
        try:
            # Handle both old format (string) and new format (dict with metadata)
            if isinstance(log_entry, dict):
                # New format with metadata (from enhanced preprocessor)
                structured = classify_log_with_retry(log_entry, agent=agent)
            else:
                # Old format (just string)
                structured = classify_log_with_retry({"line": log_entry}, agent=agent)
            
            results.append(structured)
            
            if idx % 10 == 0:  # Progress logging
                logging.info(f"Processed {idx}/{total_logs} logs...")
                
        except Exception as e:
            logging.error(f"[!] Critical error processing log {key}: {e}")
            # Create emergency fallback
            fallback = FallbackClassification.create_fallback(log_entry)
            results.append(fallback)

    # Save results
    with open(output_path, "w") as f:
        json.dump([log.dict() for log in results], f, indent=2)

    logging.info(f"Saved {len(results)} structured logs to {output_path}")
    return results

def classify_multiple_files(file_pairs: List[Tuple[str, str]], use_preloaded_agent: bool = True) -> Dict[str, List[LogsClassifier]]:
    """
    Classify multiple log files efficiently using a single agent instance.
    
    Args:
        file_pairs: List of (input_path, output_path) tuples
        use_preloaded_agent: Whether to use a preloaded agent for performance
        
    Returns:
        Dictionary mapping input paths to classification results
    """
    results = {}
    
    if use_preloaded_agent:
        # Use a single agent instance for all files (performance optimization)
        agent = get_preloaded_agent()
        logging.info(f"Processing {len(file_pairs)} files with preloaded agent")
    else:
        agent = None
        logging.info(f"Processing {len(file_pairs)} files with fresh agent instances")
    
    for input_path, output_path in file_pairs:
        try:
            logging.info(f"Processing file: {input_path}")
            file_results = classify_logs(input_path, output_path, agent=agent)
            results[input_path] = file_results
        except Exception as e:
            logging.error(f"Failed to process {input_path}: {e}")
            results[input_path] = []
    
    return results

# --------------------------------------------
# CLI Entrypoint
# --------------------------------------------

if __name__ == "__main__":
    input_file = "app/outputs/processed_logs.log"
    output_file = "app/outputs/structured_logs.json"
    classify_logs(input_file, output_file)
