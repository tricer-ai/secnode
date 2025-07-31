"""
Tricer SecNode Cloud Integration

This module provides the bridge to Tricer's commercial SaaS offerings,
enabling enterprise features like centralized policy management,
advanced analytics, and compliance reporting. The CloudSyncer operates
asynchronously to avoid impacting agent performance.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import aiohttp
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)


class CloudConfig(BaseModel):
    """Configuration for Tricer SecNode cloud services."""
    
    api_key: str = Field(..., description="Tricer API key for authentication")
    base_url: str = Field(
        default="https://api.tricer.ai/v1/",
        description="Base URL for Tricer cloud services"
    )
    batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Number of events to batch before sending"
    )
    flush_interval: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Seconds between automatic flushes"
    )
    retry_attempts: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of retry attempts for failed uploads"
    )
    timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Request timeout in seconds"
    )
    enable_analytics: bool = Field(
        default=True,
        description="Enable advanced analytics and insights"
    )
    enable_compliance: bool = Field(
        default=False,
        description="Enable compliance reporting features"
    )


class CloudSyncer:
    """
    Asynchronous cloud synchronization for SecNode telemetry and analytics.
    
    CloudSyncer provides non-blocking integration with Tricer's cloud services,
    enabling enterprise features without impacting agent performance. It batches
    events, handles retries, and provides resilient error handling.
    
    Example:
        syncer = CloudSyncer(
            api_key="your-api-key",
            batch_size=50,
            flush_interval=15
        )
        
        # Async logging (non-blocking)
        await syncer.sync_log({
            "event_type": "policy_check",
            "decision": "DENY",
            "policy": "PromptInjectionPolicy"
        })
        
        # Graceful shutdown
        await syncer.close()
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[CloudConfig] = None,
        **kwargs: Any
    ):
        """
        Initialize the CloudSyncer with configuration.
        
        Args:
            api_key: Tricer API key (can also be set via TRICER_API_KEY env var)
            config: CloudConfig object with detailed settings
            **kwargs: Additional config parameters to override defaults
        """
        if config is None:
            # Create config from individual parameters
            config_dict = {"api_key": api_key or ""} 
            config_dict.update(kwargs)
            self.config = CloudConfig(**config_dict)
        else:
            self.config = config
        
        # Initialize internal state
        self._session: Optional[aiohttp.ClientSession] = None
        self._event_buffer: List[Dict[str, Any]] = []
        self._buffer_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._closed = False
        self._stats = {
            "events_queued": 0,
            "events_sent": 0,
            "events_failed": 0,
            "batches_sent": 0,
            "api_errors": 0,
        }
        
        # Start background flush task
        if self.config.api_key:
            self._start_flush_task()
    
    def _start_flush_task(self) -> None:
        """Start the background task for periodic event flushing."""
        if not self._flush_task or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._periodic_flush())
    
    async def _periodic_flush(self) -> None:
        """Background task that periodically flushes the event buffer."""
        while not self._closed:
            try:
                await asyncio.sleep(self.config.flush_interval)
                await self.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"CloudSyncer periodic flush error: {e}")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "tricer-secnode/0.1.0",
            }
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=10)
            )
        
        return self._session
    
    async def sync_log(self, log_entry: Dict[str, Any]) -> None:
        """
        Queue a log entry for asynchronous upload to the cloud.
        
        This method is non-blocking and adds the log entry to an internal
        buffer for batch processing. Events are automatically flushed
        based on buffer size and time intervals.
        
        Args:
            log_entry: Dictionary containing the log data to upload
        """
        if self._closed or not self.config.api_key:
            return
        
        # Add timestamp and metadata
        enriched_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "tricer-secnode",
            "version": "0.1.0",
            **log_entry
        }
        
        async with self._buffer_lock:
            self._event_buffer.append(enriched_entry)
            self._stats["events_queued"] += 1
            
            # Trigger flush if buffer is full
            if len(self._event_buffer) >= self.config.batch_size:
                asyncio.create_task(self.flush())
    
    async def flush(self) -> None:
        """
        Immediately flush all buffered events to the cloud.
        
        This method sends all pending events in the buffer to Tricer's
        cloud services. It's called automatically but can also be
        invoked manually for immediate delivery.
        """
        if self._closed or not self.config.api_key:
            return
        
        # Get events to send
        async with self._buffer_lock:
            if not self._event_buffer:
                return
            
            events_to_send = self._event_buffer.copy()
            self._event_buffer.clear()
        
        # Send events in batches
        batch_size = self.config.batch_size
        for i in range(0, len(events_to_send), batch_size):
            batch = events_to_send[i:i + batch_size]
            await self._send_batch(batch)
    
    async def _send_batch(self, events: List[Dict[str, Any]]) -> None:
        """
        Send a batch of events to the cloud with retry logic.
        
        Args:
            events: List of events to send
        """
        if not events:
            return
        
        url = urljoin(self.config.base_url, "secnode/events")
        payload = {
            "events": events,
            "batch_id": f"batch_{datetime.utcnow().timestamp()}",
            "config": {
                "analytics_enabled": self.config.enable_analytics,
                "compliance_enabled": self.config.enable_compliance,
            }
        }
        
        for attempt in range(self.config.retry_attempts + 1):
            try:
                session = await self._get_session()
                
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        self._stats["events_sent"] += len(events)
                        self._stats["batches_sent"] += 1
                        
                        # Log response for debugging (optional)
                        if logger.isEnabledFor(logging.DEBUG):
                            resp_data = await response.json()
                            logger.debug(f"Cloud sync successful: {resp_data}")
                        
                        return
                    
                    elif response.status == 401:
                        logger.error("CloudSyncer authentication failed - check API key")
                        self._stats["api_errors"] += 1
                        break  # Don't retry auth errors
                    
                    elif response.status == 429:
                        # Rate limited - exponential backoff
                        wait_time = 2 ** attempt
                        logger.warning(f"Rate limited, waiting {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    
                    else:
                        # Other HTTP errors
                        error_text = await response.text()
                        logger.warning(
                            f"Cloud sync failed (attempt {attempt + 1}): "
                            f"HTTP {response.status} - {error_text}"
                        )
                        
                        if attempt < self.config.retry_attempts:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            self._stats["events_failed"] += len(events)
                            self._stats["api_errors"] += 1
            
            except asyncio.TimeoutError:
                logger.warning(f"Cloud sync timeout (attempt {attempt + 1})")
                if attempt >= self.config.retry_attempts:
                    self._stats["events_failed"] += len(events)
            
            except Exception as e:
                logger.warning(f"Cloud sync error (attempt {attempt + 1}): {e}")
                if attempt >= self.config.retry_attempts:
                    self._stats["events_failed"] += len(events)
    
    async def sync_policy_update(
        self,
        policy_name: str,
        policy_config: Dict[str, Any],
        version: str = "1.0"
    ) -> Optional[Dict[str, Any]]:
        """
        Sync policy configuration to the cloud for centralized management.
        
        Args:
            policy_name: Name of the policy
            policy_config: Policy configuration dictionary
            version: Policy version string
            
        Returns:
            Updated policy configuration from cloud, or None if failed
        """
        if self._closed or not self.config.api_key:
            return None
        
        url = urljoin(self.config.base_url, "secnode/policies")
        payload = {
            "policy_name": policy_name,
            "config": policy_config,
            "version": version,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        try:
            session = await self._get_session()
            
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"Policy sync failed: HTTP {response.status}")
                    return None
        
        except Exception as e:
            logger.warning(f"Policy sync error: {e}")
            return None
    
    async def get_analytics(
        self,
        time_range: str = "24h",
        filters: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve analytics data from the cloud.
        
        Args:
            time_range: Time range for analytics (e.g., "1h", "24h", "7d")
            filters: Optional filters for the analytics query
            
        Returns:
            Analytics data dictionary, or None if failed
        """
        if self._closed or not self.config.api_key or not self.config.enable_analytics:
            return None
        
        url = urljoin(self.config.base_url, "secnode/analytics")
        params = {"time_range": time_range}
        
        if filters:
            params["filters"] = json.dumps(filters)
        
        try:
            session = await self._get_session()
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"Analytics request failed: HTTP {response.status}")
                    return None
        
        except Exception as e:
            logger.warning(f"Analytics request error: {e}")
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get CloudSyncer usage statistics."""
        return {
            **self._stats,
            "buffer_size": len(self._event_buffer),
            "success_rate": (
                self._stats["events_sent"] / 
                max(1, self._stats["events_sent"] + self._stats["events_failed"])
            ),
            "is_active": not self._closed and bool(self.config.api_key),
        }
    
    async def close(self) -> None:
        """
        Gracefully close the CloudSyncer.
        
        This method flushes any remaining events, cancels background tasks,
        and closes network connections. Should be called during application
        shutdown for clean resource cleanup.
        """
        if self._closed:
            return
        
        self._closed = True
        
        # Cancel background flush task
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self.flush()
        
        # Close HTTP session
        if self._session and not self._session.closed:
            await self._session.close()
        
        logger.info("CloudSyncer closed gracefully")
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()