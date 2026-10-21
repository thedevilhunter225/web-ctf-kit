"""Reporting: Markdown, JSON, and a Rich-or-plain terminal summary."""
from .json_report import load_result, save_report
from .markdown import as_markdown
from .console import print_banner, print_summary

__all__ = ["as_markdown", "save_report", "load_result", "print_summary", "print_banner"]
