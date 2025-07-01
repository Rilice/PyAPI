import logging
import logging.handlers
import json
import datetime
import socket
import os

#*--**--**--**--**--**--**--**--**--**--*
# JSON Formatter
#*--**--**--**--**--**--**--**--**--**--*

class JSONLogFormatter(logging.Formatter):
    def __init__(self, service_name=None, environment=None, event_type=None):
        super().__init__()
        try:
            self.host = socket.gethostname()
            self.ip_address = socket.gethostbyname(self.host)
        except Exception:
            self.host = "unknown"
            self.ip_address = "unknown"
        self.service_name = service_name or os.getenv("SERVICE_NAME","PumaIntegrationService")
        self.environment = environment or os.getenv("PIS_ENVIRONMENT",'dev').lower()
        self.default_event_type = event_type

    def format(self, record):
        record_dict = {
            "timestamp": datetime.datetime.now().isoformat(timespec="milliseconds"),
            "log_level": record.levelname,
            "message": record.getMessage(),
            "event_type": {
                "event_name": getattr(record, "event_type", None) or self.default_event_type,
                "event_sub_name": getattr(record, "event_sub_name", None),
            },
            "context_guid": getattr(record, "context_guid", None),
            "event_host_info": getattr(record, "event_host_info", {
                "service_name": self.service_name,
                "host": self.host,
                "ip_address": self.ip_address,
                "environment": self.environment,
            }),
            "request_info": getattr(record, "request_info", None),
            "execution_info": getattr(record, "execution_info", None),
            "error": getattr(record, "error", None),
            "extra": getattr(record, "extra", None),
        }
        # Добавим trace, если есть исключение
        if record.exc_info:
            record_dict["error"] = record_dict["error"] or {}
            record_dict["error"]["traceback"] = self.formatException(record.exc_info)
        # Чистим None
        clean_record = {k: v for k, v in record_dict.items() if v is not None}
        return json.dumps(clean_record, ensure_ascii=False)

#*--**--**--**--**--**--**--**--**--**--*
# LoggerAdapter для контекста
#*--**--**--**--**--**--**--**--**--**--*
class ModuleLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra):
        super().__init__(logger, extra)
    def process(self, msg, kwargs):
        if 'extra' in kwargs and not isinstance(kwargs['extra'], dict):
            raise ValueError(f"extra must be dict, not {type(kwargs['extra'])}")
        if 'extra' in kwargs:
            kwargs['extra'] = {**self.extra, **kwargs['extra']}
        else:
            kwargs['extra'] = self.extra.copy()
        return msg, kwargs

#*--**--**--**--**--**--**--**--**--**--*
# Фильтр для root (чтобы резать DEBUG)
#*--**--**--**--**--**--**--**--**--**--*
class RespectRootLevelFilter(logging.Filter):
    def filter(self, record):
        # Берём root-логгер
        root_logger = logging.getLogger()
        return record.levelno >= root_logger.level

#*--**--**--**--**--**--**--**--**--**--*
# Root Logger Setup
#*--**--**--**--**--**--**--**--**--**--*

def setup_root_logger(
    logfile,
    formatter,
    to_console=True,
    level=logging.INFO,
    max_bytes=10 * 1024 * 1024,
    backup_count=5,
):
    logger = logging.getLogger()  # root
    logger.setLevel(level)
    logger.handlers.clear()

    fh = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    fh.doRollover()

    fh.setLevel(level)
    fh.setFormatter(formatter)
    fh.addFilter(RespectRootLevelFilter())
    
    logger.addHandler(fh)
    

    if to_console:
        sh = logging.StreamHandler()
        sh.setLevel(level)
        sh.setFormatter(formatter)
        sh.addFilter(RespectRootLevelFilter())
        logger.addHandler(sh)

    return logger

#*--**--**--**--**--**--**--**--**--**--*
# Module Logger Setup
#*--**--**--**--**--**--**--**--**--**--*
def setup_module_logger(
    module_name,
    logfile,
    formatter,
    level=logging.DEBUG,
    max_bytes=5 * 1024 * 1024,
    backup_count=2,
    propagate=True,
):
    logger = logging.getLogger(module_name)
    logger.setLevel(level)
    logger.handlers.clear()

    mh = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    mh.doRollover()
    mh.setLevel(level)
    mh.setFormatter(formatter)
    logger.addHandler(mh)

    logger.propagate = propagate
    return logger


#*--**--**--**--**--**--**--**--**--**--*
# Быстрый адаптер для одного модуля
#*--**--**--**--**--**--**--**--**--**--*
def get_context_logger(logger, event_type):
    return ModuleLoggerAdapter(logger, {"event_type": event_type})