"""
Extractors module for api-tool spider.
Provides:
- FastHydrationScraper: Sub-millisecond SPA and hydration harvester
- DOMExtractor: Interactive DOM endpoint and HTMX extractor
- HTMXEndpoint: Discovered HTMX endpoint representation
- FormExtractor: HTML form and action endpoint extractor
- FormControl: Discovered HTML form control representation
- FormPayloadGenerator: Realistic form submission payload generator
"""

from api_tool.spider.extractors.hydration_extractor import FastHydrationScraper

from api_tool.spider.extractors.dom_extractor import DOMExtractor, HTMXEndpoint
from api_tool.spider.extractors.form_extractor import (
    FormControl,
    FormExtractor,
    FormPayloadGenerator,
)

__all__ = [
    "FastHydrationScraper",
    "DOMExtractor",
    "FormControl",
    "FormExtractor",
    "FormPayloadGenerator",
    "HTMXEndpoint",
]
