"""
HAR 1.2 Ingestion Engine for api-tool.
Exports HARImporter for parsing and transforming HTTP Archive files into ScanResult IR.
"""

from api_tool.importer.har_importer import HARImporter

__all__ = ["HARImporter"]
