import json
import logging
import queue
import threading
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class SSEBroadcaster:
    """
    Thread-safe Publisher/Subscriber broadcaster for Server-Sent Events (SSE).
    Distributes real-time security events, authentication telemetry, and alert notifications
    to all active SOC analyst browser dashboards without polling overhead.
    """
    _subscribers: List[queue.Queue] = []
    _lock = threading.Lock()

    @classmethod
    def subscribe(cls) -> queue.Queue:
        """Register a new browser client SSE listener queue."""
        q: queue.Queue = queue.Queue(maxsize=60)
        with cls._lock:
            cls._subscribers.append(q)
            logger.debug(f"New SSE client connected. Total active subscribers: {len(cls._subscribers)}")
        return q

    @classmethod
    def unsubscribe(cls, q: queue.Queue) -> None:
        """Remove a disconnected browser client listener queue."""
        with cls._lock:
            if q in cls._subscribers:
                cls._subscribers.remove(q)
                logger.debug(f"SSE client disconnected. Active subscribers: {len(cls._subscribers)}")

    @classmethod
    def publish(cls, event_type: str, data: Dict[str, Any]) -> None:
        """
        Broadcast an event to all connected browser SSE listeners.
        Drops messages if a client buffer overflows (slow consumer safeguard).
        """
        payload = {
            'event': event_type,
            'data': data
        }
        with cls._lock:
            dead_queues = []
            for q in cls._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead_queues.append(q)
            for dead_q in dead_queues:
                if dead_q in cls._subscribers:
                    cls._subscribers.remove(dead_q)

    @classmethod
    def active_subscribers_count(cls) -> int:
        """Return the number of active SSE client listeners."""
        with cls._lock:
            return len(cls._subscribers)
