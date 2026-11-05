"""Simplified data models for database round-tripping."""

from src.scanner.models import ScanResult

# Re-export the scan result model so callers can use one canonical type.
__all__ = ["ScanResult"]

# keep a placeholder for parity with the documented structure
ScanResult = ScanResult