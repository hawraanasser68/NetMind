import structlog
from src.infra.infra_redaction import redact


def _redaction_processor(logger, method, event_dict):
    """
    Structlog processor — redacts all string values before the log line is written.
    Runs on every log call across every service automatically.
    """
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = redact(value)
    return event_dict


def configure_logging():
    """
    Configure structlog for the calling service.
    Call once at the top of each service's main.py before anything else.
    Outputs structured JSON with automatic redaction on every line.
    """
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt='iso'),
            structlog.stdlib.add_log_level,
            _redaction_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class  = structlog.make_filtering_bound_logger(20),  # 20 = INFO level
        context_class  = dict,
        logger_factory = structlog.PrintLoggerFactory(),
    )
