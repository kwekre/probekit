from .base import Detector
from .sqli import SQLiDetector
from .xss import XSSDetector
from .ssrf import SSRFDetector
from .openredirect import OpenRedirectDetector
from .command_injection import CommandInjectionDetector
from .path_traversal import PathTraversalDetector
from .jwt import JwtDetector

ALL_DETECTORS = [
    SQLiDetector, XSSDetector, SSRFDetector, OpenRedirectDetector,
    CommandInjectionDetector, PathTraversalDetector, JwtDetector,
]

__all__ = [
    "Detector", "SQLiDetector", "XSSDetector", "SSRFDetector",
    "OpenRedirectDetector", "CommandInjectionDetector",
    "PathTraversalDetector", "JwtDetector", "ALL_DETECTORS",
]
