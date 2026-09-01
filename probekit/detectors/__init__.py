from .base import Detector
from .sqli import SQLiDetector
from .xss import XSSDetector
from .ssrf import SSRFDetector
from .openredirect import OpenRedirectDetector

ALL_DETECTORS = [SQLiDetector, XSSDetector, SSRFDetector, OpenRedirectDetector]

__all__ = ["Detector", "SQLiDetector", "XSSDetector", "SSRFDetector",
           "OpenRedirectDetector", "ALL_DETECTORS"]
