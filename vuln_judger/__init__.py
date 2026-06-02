"""LLM-assisted static vulnerability adjudication from reports and source code."""

from .pipeline import run_judgement

__all__ = ["run_judgement"]
