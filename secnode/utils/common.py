"""
Common utility functions for SecNode policies.

This module provides reusable functions that are commonly used across
different security policies to reduce code duplication.
"""

import re
from typing import Any, Dict, List, Optional, Union


class PolicyUtils:
    """Utility class containing common functions for security policies."""
    
    @staticmethod
    def extract_content_from_state(state: Dict[str, Any]) -> List[str]:
        """
        Extract text content from various state fields.
        
        This function looks for common fields that contain text content
        and returns a list of strings to be analyzed by security policies.
        
        Args:
            state: The agent state dictionary
            
        Returns:
            List of text content strings found in the state
        """
        content_to_check = []
        
        # Extract content from messages
        if "messages" in state:
            for msg in state["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    if isinstance(msg["content"], str):
                        content_to_check.append(msg["content"])
                elif isinstance(msg, str):
                    content_to_check.append(msg)
        
        # Extract from common text fields
        text_fields = ["user_input", "query", "prompt", "text", "content"]
        for field in text_fields:
            if field in state and state[field]:
                content_to_check.append(str(state[field]))
        
        # Filter out empty strings
        return [content for content in content_to_check if content.strip()]
    
    @staticmethod
    def extract_output_content(state: Dict[str, Any]) -> List[str]:
        """
        Extract output content from state for leakage detection.
        
        Args:
            state: The agent state dictionary
            
        Returns:
            List of output content strings
        """
        content_to_check = []
        
        # Focus on output content that might contain leakage
        output_fields = ["response", "output", "result", "error", "debug"]
        for field in output_fields:
            if field in state and state[field]:
                content_to_check.append(str(state[field]))
        
        return [content for content in content_to_check if content.strip()]
    
    @staticmethod
    def calculate_risk_score(
        base_factors: List[float], 
        multiplier: float = 1.0,
        max_score: float = 1.0
    ) -> float:
        """
        Calculate a normalized risk score from multiple factors.
        
        Args:
            base_factors: List of risk factors (0.0 to 1.0)
            multiplier: Multiplier to apply to the combined score
            max_score: Maximum allowed score
            
        Returns:
            Normalized risk score between 0.0 and max_score
        """
        if not base_factors:
            return 0.0
        
        # Calculate weighted average of factors
        combined_score = sum(base_factors) / len(base_factors)
        
        # Apply multiplier and cap at max_score
        final_score = min(max_score, combined_score * multiplier)
        
        return max(0.0, final_score)
    
    @staticmethod
    def extract_urls_from_text(text: str) -> List[str]:
        """
        Extract URLs from text using regex patterns.
        
        Args:
            text: Text to search for URLs
            
        Returns:
            List of URLs found in the text
        """
        # Common URL patterns
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'ftp://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[^\s<>"{}|\\^`\[\]]+',
        ]
        
        urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(matches)
        
        return list(set(urls))  # Remove duplicates
    
    @staticmethod
    def extract_code_blocks(text: str) -> List[Dict[str, str]]:
        """
        Extract code blocks from text (markdown format).
        
        Args:
            text: Text containing potential code blocks
            
        Returns:
            List of dictionaries with 'language' and 'code' keys
        """
        code_blocks = []
        
        # Pattern for fenced code blocks
        pattern = r'```(\w+)?\n(.*?)\n```'
        matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
        
        for language, code in matches:
            code_blocks.append({
                'language': language.lower() if language else 'unknown',
                'code': code.strip()
            })
        
        return code_blocks
    
    @staticmethod
    def normalize_text(text: str, lowercase: bool = True) -> str:
        """
        Normalize text for consistent processing.
        
        Args:
            text: Text to normalize
            lowercase: Whether to convert to lowercase
            
        Returns:
            Normalized text
        """
        if not isinstance(text, str):
            return ""
        
        # Remove extra whitespace
        normalized = ' '.join(text.split())
        
        if lowercase:
            normalized = normalized.lower()
        
        return normalized
    
    @staticmethod
    def safe_get_nested(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
        """
        Safely get nested dictionary values.
        
        Args:
            data: Dictionary to search
            keys: List of keys for nested access
            default: Default value if key path not found
            
        Returns:
            Value at the key path or default
        """
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current