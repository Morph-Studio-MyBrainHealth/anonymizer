from typing import List, Optional
from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer

class ZipRecognizer(PatternRecognizer):
    """
    Recognizes ZIP code patterns using regex.
    Supports:
    - 5-digit format (US)
    - 6-digit format (common in other countries)
    - 9-digit ZIP+4 format (US extended)
    """

    PATTERNS = [
        Pattern(
            "ZIP (5-digit)",
            r"\b\d{5}\b",
            0.6,  # Medium confidence for 5-digit
        ),
        Pattern(
            "ZIP (6-digit)", 
            r"\b\d{6}\b",
            0.6,  # Medium confidence for 6-digit
        ),
        Pattern(
            "ZIP+4 (high confidence)", 
            r"\b\d{5}[-]\d{4}\b",
            0.8,  # Higher confidence for ZIP+4 format
        )
    ]

    CONTEXT = ["zip", "zipcode", "zip code", "postal", "post", "code", "address"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity="ZIP",
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name="ZipRecognizer"
        )
