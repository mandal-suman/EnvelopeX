"""
EnvelopeX Core Module
Email forensics analysis components
"""

from .analyzer import EmailForensicsAnalyzer
from .parser import parse_eml_bytes, compute_hashes_bytes

__all__ = [
    'EmailForensicsAnalyzer',
    'parse_eml_bytes',
    'compute_hashes_bytes'
]
