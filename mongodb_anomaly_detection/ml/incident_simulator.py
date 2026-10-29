"""
Realistic incident simulation for demos.

Writes logs for the last few minutes in which user-service's database slows
down, auth-service then times out calling user-service, and payment-service
fails after that because both of its dependencies are unhealthy.
"""

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List

from models.log_schema import LogEntry

REQUESTS_PER_MINUTE = 12

# (service, minutes before now its failure starts), in cascade order
CASCADE_STEPS = [
    ("user-service", 6),
    ("auth-service", 4),
    ("payment-service", 3),
]


def _user_service_log(rng: random.Random) -> Dict[str, Any]:
    roll = rng.random()
    if roll < 0.15:
        return dict(log_level="ERROR", message="Database connection timeout", endpoint="/api/users/profile",
                    status_code=503, response_time_ms=rng.uniform(5000, 6000))
    if roll < 0.45:
        return dict(log_level="WARNING", message="Slow database query: connection pool exhausted",
                    endpoint="/api/users/profile", status_code=200, response_time_ms=rng.uniform(2500, 4500))
    return dict(log_level="INFO", message="Request completed", endpoint="/api/users",
                status_code=200, response_time_ms=rng.uniform(1800, 3500))


def _auth_service_log(rng: random.Random) -> Dict[str, Any]:
    if rng.random() < 0.7:
        return dict(log_level="ERROR", message="Upstream timeout calling user-service",
                    endpoint="/api/token/refresh", status_code=504, response_time_ms=rng.uniform(3000, 5000))
    return dict(log_level="INFO", message="Request completed", endpoint="/api/login",
                status_code=200, response_time_ms=rng.uniform(80, 250))


def _payment_service_log(rng: random.Random) -> Dict[str, Any]:
    roll = rng.random()
    if roll < 0.55:
        return dict(log_level="ERROR", message="Token validation failed: auth-service unavailable",
                    endpoint="/api/payment", status_code=502, response_time_ms=rng.uniform(2000, 4000))
    if roll < 0.75:
        return dict(log_level="ERROR", message="Upstream timeout calling user-service",
                    endpoint="/api/payment", status_code=504, response_time_ms=rng.uniform(3000, 5000))
    return dict(log_level="INFO", message="Request completed", endpoint="/api/payment/status",
                status_code=200, response_time_ms=rng.uniform(100, 400))


LOG_FACTORIES = {
    "user-service": _user_service_log,
    "auth-service": _auth_service_log,
    "payment-service": _payment_service_log,
}


def build_cascade_logs(end: datetime, rng: random.Random, steps=CASCADE_STEPS) -> List[Dict[str, Any]]:
    """
    Cascading-failure logs ending at `end`.

    `steps` lists (service, minutes before `end` its failure starts) in cascade order.
    """
    documents: List[Dict[str, Any]] = []
    for service, start_minutes in steps:
        for i in range(start_minutes * REQUESTS_PER_MINUTE):
            timestamp = end - timedelta(minutes=start_minutes) + timedelta(seconds=i * 60 / REQUESTS_PER_MINUTE)
            fields = LOG_FACTORIES[service](rng)
            fields["response_time_ms"] = round(fields["response_time_ms"], 1)
            log = LogEntry(
                timestamp=timestamp,
                service_name=service,
                http_method="POST" if "payment" in fields["endpoint"] or "token" in fields["endpoint"] else "GET",
                metadata={"simulation": "cascading_failure", "scenario": "cascading_failure"},
                **fields,
            )
            documents.append(log.dict(by_alias=True))
    return documents


def simulate_cascading_failure(db, seed: int = None) -> Dict[str, Any]:
    """Insert the cascading-failure logs and return what was written per service."""
    now = datetime.utcnow()
    documents = build_cascade_logs(now, random.Random(seed))
    db["log_entries"].insert_many(documents)

    written: Dict[str, int] = {}
    for doc in documents:
        written[doc["service_name"]] = written.get(doc["service_name"], 0) + 1
    return {
        "scenario": "cascading_failure",
        "description": "user-service database slows down, then auth-service and payment-service fail calling it",
        "logs_written": written,
        "started_at": now - timedelta(minutes=CASCADE_STEPS[0][1]),
    }
