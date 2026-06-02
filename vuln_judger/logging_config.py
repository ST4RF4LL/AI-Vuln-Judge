from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


DEFAULT_LOG_FILE = Path(".vuln-judger") / "logs" / "vuln-judger.log"
ROOT_LOGGER = logging.getLogger("vuln_judger")
ROOT_LOGGER.addHandler(logging.NullHandler())
ROOT_LOGGER.propagate = False


def configure_logging(log_file: Optional[Path] = None) -> Path:
    path = (log_file or DEFAULT_LOG_FILE).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    root = ROOT_LOGGER
    root.setLevel(logging.INFO)
    for handler in list(root.handlers):
        if getattr(handler, "_vuln_judger_handler", False):
            root.removeHandler(handler)
            handler.close()

    handler = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    handler._vuln_judger_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.propagate = False
    root.info("日志初始化完成：%s", path)
    return path


def logger(name: str) -> logging.Logger:
    return logging.getLogger(f"vuln_judger.{name}")
