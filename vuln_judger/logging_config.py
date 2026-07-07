from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable, Optional


DEFAULT_LOG_FILE = Path(".vuln-judger") / "logs" / "vuln-judger.log"
DEFAULT_LOG_RETENTION_DAYS = 31
ROOT_LOGGER = logging.getLogger("vuln_judger")
ROOT_LOGGER.addHandler(logging.NullHandler())
ROOT_LOGGER.propagate = False

_BASE_RECORD_KEYS = set(logging.makeLogRecord({}).__dict__)
_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_./:@+\-=]+$")


class KeyValueFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
        }
        for key in sorted(record.__dict__):
            if key in _BASE_RECORD_KEYS or key.startswith("_"):
                continue
            fields[key] = record.__dict__[key]
        fields["msg"] = record.getMessage()
        if record.exc_info:
            fields["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            fields["stack_info"] = self.formatStack(record.stack_info)
        return " ".join(_format_log_field(key, value) for key, value in fields.items() if value is not None)

    def formatTime(self, record: logging.LogRecord, datefmt: Optional[str] = None) -> str:  # noqa: N802
        dt = datetime.fromtimestamp(record.created).astimezone()
        if datefmt:
            return dt.strftime(datefmt)
        base = dt.strftime("%Y-%m-%dT%H:%M:%S")
        tz = dt.strftime("%z")
        if tz:
            tz = f"{tz[:3]}:{tz[3:]}"
        return f"{base}.{int(record.msecs):03d}{tz}"


class DailyFileHandler(logging.Handler):
    def __init__(
        self,
        log_target: Path,
        *,
        retention_days: int = DEFAULT_LOG_RETENTION_DAYS,
        encoding: str = "utf-8",
        today: Optional[Callable[[], date]] = None,
    ) -> None:
        super().__init__()
        self.directory, self.prefix = _daily_log_target(log_target)
        self.retention_days = max(1, int(retention_days))
        self.encoding = encoding
        self._today = today or date.today
        self.current_day: Optional[date] = None
        self.current_path: Optional[Path] = None
        self.stream = None
        self.directory.mkdir(parents=True, exist_ok=True)
        self._cleanup_old_logs()
        self._open_for_day(self._today())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            today = self._today()
            if self.current_day != today or self.stream is None:
                self._open_for_day(today)
                self._cleanup_old_logs()
            message = self.format(record)
            self.stream.write(message + "\n")
            self.flush()
        except Exception:
            self.handleError(record)

    def flush(self) -> None:
        if self.stream is not None:
            self.stream.flush()

    def close(self) -> None:
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            self.stream = None
            super().close()

    def _open_for_day(self, day: date) -> None:
        if self.stream is not None:
            self.stream.close()
        self.current_day = day
        self.current_path = daily_log_path_for_target(self.directory, self.prefix, day)
        self.stream = self.current_path.open("a", encoding=self.encoding)

    def _cleanup_old_logs(self) -> None:
        cutoff = self._today() - timedelta(days=self.retention_days - 1)
        for path in self.directory.glob(f"{self.prefix}-*.log"):
            log_day = _date_from_daily_log_name(path, self.prefix)
            if log_day is not None and log_day < cutoff:
                try:
                    path.unlink()
                except OSError:
                    continue


def configure_logging(
    log_file: Optional[Path] = None,
    *,
    retention_days: int = DEFAULT_LOG_RETENTION_DAYS,
) -> Path:
    path = (log_file or DEFAULT_LOG_FILE).expanduser().resolve()

    root = ROOT_LOGGER
    root.setLevel(logging.INFO)
    for handler in list(root.handlers):
        if getattr(handler, "_vuln_judger_handler", False):
            root.removeHandler(handler)
            handler.close()

    handler = DailyFileHandler(path, retention_days=retention_days)
    handler.setFormatter(KeyValueFormatter())
    handler._vuln_judger_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.propagate = False
    root.info(
        "日志初始化完成",
        extra={
            "event": "log.init",
            "log_file": str(handler.current_path),
            "retention_days": handler.retention_days,
        },
    )
    if handler.current_path is None:
        raise RuntimeError("日志文件初始化失败")
    return handler.current_path


def daily_log_path(log_file: Optional[Path] = None, *, day: Optional[date] = None) -> Path:
    directory, prefix = _daily_log_target((log_file or DEFAULT_LOG_FILE).expanduser())
    return daily_log_path_for_target(directory, prefix, day or date.today())


def daily_log_path_for_target(directory: Path, prefix: str, day: date) -> Path:
    return directory / f"{prefix}-{day.isoformat()}.log"


def logger(name: str) -> logging.Logger:
    return logging.getLogger(f"vuln_judger.{name}")


def _daily_log_target(path: Path) -> tuple[Path, str]:
    normalized = path.expanduser()
    if normalized.suffix:
        prefix = normalized.stem or "vuln-judger"
        return normalized.parent, _safe_log_prefix(prefix)
    return normalized, "vuln-judger"


def _safe_log_prefix(prefix: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", prefix).strip(".-")
    return cleaned or "vuln-judger"


def _date_from_daily_log_name(path: Path, prefix: str) -> Optional[date]:
    match = re.fullmatch(rf"{re.escape(prefix)}-(\d{{4}}-\d{{2}}-\d{{2}})\.log", path.name)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def _format_log_field(key: str, value: object) -> str:
    return f"{_safe_log_key(key)}={_format_log_value(value)}"


def _safe_log_key(key: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(key)).strip("_")
    return cleaned or "field"


def _format_log_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (dict, list, tuple)):
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        if any(char.isspace() for char in encoded):
            return json.dumps(encoded, ensure_ascii=False)
        return encoded
    text = str(value)
    if text and _SAFE_VALUE_RE.fullmatch(text):
        return text
    return json.dumps(text, ensure_ascii=False)
