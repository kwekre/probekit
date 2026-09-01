from .base import Detector
from .sqli import SQLiDetector
from .xss import XSSDetector
from .ssrf import SSRFDetector
from .openredirect import OpenRedirectDetector
from .command_injection import CommandInjectionDetector
from .path_traversal import PathTraversalDetector
from .jwt import JwtDetector
from .info_leak import InfoLeakDetector
from .cors import CorsDetector

ALL_DETECTORS = [
    SQLiDetector, XSSDetector, SSRFDetector, OpenRedirectDetector,
    CommandInjectionDetector, PathTraversalDetector, JwtDetector,
    InfoLeakDetector, CorsDetector,
]

__all__ = [
    "Detector", "SQLiDetector", "XSSDetector", "SSRFDetector",
    "OpenRedirectDetector", "CommandInjectionDetector",
    "PathTraversalDetector", "JwtDetector", "InfoLeakDetector",
    "CorsDetector", "ALL_DETECTORS",
]
