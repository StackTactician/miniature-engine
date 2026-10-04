"""
Analyzer Module for api-tool.
Provides:
- SourceMapUnpacker: High-performance source map extraction and original file reconstruction
- SourceMapFile: Dataclass for extracted original source files
- SourceMapResult: Dataclass containing unpacked source files, endpoints, and framework metadata
- SourceMapReference: Reference container for JavaScript source map directives
- sanitize_source_path: Strict path traversal and Zip Slip sanitization utility
- JSRegexExtractor: Static Regex & HTTP client harvester
"""

from api_tool.analyzer.sourcemap import (
    SourceMapFile,
    SourceMapReference,
    SourceMapResult,
    SourceMapUnpacker,
    sanitize_source_path,
)

try:
    from api_tool.analyzer.js_regex import JSRegexExtractor
except ImportError:
    JSRegexExtractor = None

from api_tool.models import DiscoveredChunkManifest, PersistedQueryRecord
from api_tool.analyzer.chunk_cracker import ChunkMapCracker
from api_tool.analyzer.graphql_parser import GraphQLQueryExtractor
from api_tool.analyzer.apq_extractor import APQOperationExtractor
from api_tool.analyzer.ast_parser import JSASTExtractor
from api_tool.analyzer.coordinator import StaticAnalyzer, StaticAnalysisResult

__all__ = [
    "SourceMapFile",
    "SourceMapReference",
    "SourceMapResult",
    "SourceMapUnpacker",
    "sanitize_source_path",
    "GraphQLQueryExtractor",
    "StaticAnalyzer",
    "StaticAnalysisResult",
    "ChunkMapCracker",
    "DiscoveredChunkManifest",
    "APQOperationExtractor",
    "PersistedQueryRecord",
    "JSASTExtractor",
]
if JSRegexExtractor is not None:
    __all__.append("JSRegexExtractor")


