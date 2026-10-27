"""
AI incident investigator.

Starting from one detected anomaly, it gathers the related anomalies of every
service around the same time, rebuilds a per-minute timeline from the raw
logs, ranks root-cause hypotheses using the service dependency map, and
collects numbered evidence from MongoDB. A local LLM (Ollama) then writes the
incident report, citing that evidence.

Safety: the investigator only reads data. The LLM has no tools, its output is
checked for citations of real evidence, and any destructive suggestion is
flagged as requiring human approval. Nothing is ever executed automatically.
"""

import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "180"))

# Which services each service calls. A failure in a dependency can cascade
# to the services that call it.
SERVICE_DEPENDENCIES = {
    "auth-service": ["user-service"],
    "payment-service": ["auth-service", "user-service"],
    "user-service": [],
}

CORRELATION_MINUTES = 15
BASELINE_WINDOWS = 60

SIGNAL_BY_RULE = {
    "high_error_rate": "errors",
    "very_high_error_rate": "errors",
    "sudden_error_spike": "errors",
    "high_latency_p95": "latency",
    "high_latency_p99": "latency",
    "low_traffic": "traffic",
    "sudden_traffic_drop": "traffic",
}

# Read-only checks suggested for each kind of signal
CHECKS_BY_SIGNAL = {
    "errors": "Inspect the error logs and stack traces of {service} for {detail}, and check whether a deployment or config change happened just before {onset}.",
    "latency": "Check {service}'s database and downstream call latency (slow query log, connection pool usage) around {onset}.",
    "traffic": "Check the load balancer and health checks in front of {service}; confirm whether clients are failing before they reach it.",
    "pattern": "Compare {service}'s request mix (endpoints, status codes, payload sizes) with the baseline; the model flagged an unusual combination.",
}

# Words that indicate a state-changing action; such suggestions need a human
DESTRUCTIVE_PATTERN = re.compile(
    r"\b(restart\w*|reboot\w*|kill\w*|terminat\w*|delet\w*|truncat\w*|purg\w*|wip(?:e|ed|ing)|"
    r"flush\w*|disabl\w*|redeploy\w*|rm\s+-rf|drop\s+(?:table|database|collection)|"
    r"shut(?:ting)?\s*down|roll(?:ing)?\s*back|rollback|scal(?:e|ing)\s+down)\b",
    re.IGNORECASE,
)

# Ollama runs locally, so never send its requests through an HTTP proxy
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class InvestigationError(Exception):
    """Raised when an investigation cannot be started."""


def _round(value, digits=3):
    return round(value, digits) if isinstance(value, (int, float)) else value


def _fmt(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


class EvidenceLog:
    """Numbered evidence items that conclusions must refer to."""

    def __init__(self):
        self.items: List[Dict[str, Any]] = []

    def add(self, kind: str, service: str, description: str, source: Dict[str, Any],
            time: Optional[datetime] = None) -> str:
        evidence_id = f"E{len(self.items) + 1}"
        self.items.append({
            "id": evidence_id,
            "type": kind,
            "service": service,
            "time": time,
            "description": description,
            "source": source,
        })
        return evidence_id


def _baseline(db, service: str, before: datetime) -> Dict[str, float]:
    """Average window metrics of the service before the incident."""
    result = list(db["window_features"].aggregate([
        {"$match": {"service_name": service, "window_start": {"$lt": before}}},
        {"$sort": {"window_start": -1}},
        {"$limit": BASELINE_WINDOWS},
        {"$group": {
            "_id": None,
            "requests_per_minute": {"$avg": {"$divide": ["$request_count", "$window_size_minutes"]}},
            "error_rate": {"$avg": "$error_rate"},
            "avg_response_time_ms": {"$avg": "$avg_response_time_ms"},
            "p95_response_time_ms": {"$avg": "$p95_response_time_ms"},
            "windows": {"$sum": 1},
        }},
    ]))
    return result[0] if result else {}


def _minute_series(db, service: str, start: datetime, end: datetime) -> List[Dict[str, Any]]:
    """Per-minute request count, error rate and latency from the raw logs."""
    return list(db["log_entries"].aggregate([
        {"$match": {"service_name": service, "timestamp": {"$gte": start, "$lt": end}}},
        {"$group": {
            "_id": {"$dateTrunc": {"date": "$timestamp", "unit": "minute"}},
            "requests": {"$sum": 1},
            "errors": {"$sum": {"$cond": [{"$eq": ["$log_level", "ERROR"]}, 1, 0]}},
            "avg_response_time_ms": {"$avg": "$response_time_ms"},
        }},
        {"$sort": {"_id": 1}},
    ]))


ONSET_MIN_ERRORS = 3
ONSET_SUSTAINED_MINUTES = 2


def _abnormal_signal(minute: Dict[str, Any], baseline: Dict[str, float]) -> Optional[Dict[str, Any]]:
    """Return the signal if this minute clearly departs from the baseline."""
    if minute["requests"] < 2:
        return None
    base_error = baseline.get("error_rate") or 0.0
    base_latency = baseline.get("avg_response_time_ms") or 0.0
    error_rate = minute["errors"] / minute["requests"]
    latency = minute["avg_response_time_ms"] or 0.0
    if minute["errors"] >= ONSET_MIN_ERRORS and error_rate >= max(0.3, 5 * base_error):
        return {"time": minute["_id"], "signal": "errors", "value": error_rate}
    if base_latency and latency >= 3 * base_latency:
        return {"time": minute["_id"], "signal": "latency", "value": latency}
    return None


def _find_onset(series: List[Dict[str, Any]], baseline: Dict[str, float]) -> Optional[Dict[str, Any]]:
    """
    First minute of a sustained departure from the baseline.

    A single noisy minute (a couple of errors in normal traffic) is ignored:
    the abnormal state must last ONSET_SUSTAINED_MINUTES consecutive minutes,
    unless it starts in the most recent minute of data.
    """
    signals = [_abnormal_signal(minute, baseline) for minute in series]
    for i, signal in enumerate(signals):
        if signal is None:
            continue
        run = signals[i:i + ONSET_SUSTAINED_MINUTES]
        if all(run) and (len(run) == ONSET_SUSTAINED_MINUTES or i == len(signals) - 1):
            return signal
    return None


def _service_metrics(db, service: str, start: datetime, end: datetime) -> Dict[str, Any]:
    result = list(db["log_entries"].aggregate([
        {"$match": {"service_name": service, "timestamp": {"$gte": start, "$lt": end}}},
        {"$group": {
            "_id": None,
            "requests": {"$sum": 1},
            "errors": {"$sum": {"$cond": [{"$eq": ["$log_level", "ERROR"]}, 1, 0]}},
            "avg_response_time_ms": {"$avg": "$response_time_ms"},
            "p95_response_time_ms": {"$percentile": {
                "input": "$response_time_ms", "p": [0.95], "method": "approximate"}},
        }},
    ]))
    if not result:
        return {}
    doc = result[0]
    return {
        "requests": doc["requests"],
        "error_rate": doc["errors"] / max(doc["requests"], 1),
        "avg_response_time_ms": doc["avg_response_time_ms"] or 0.0,
        "p95_response_time_ms": (doc["p95_response_time_ms"] or [0.0])[0] or 0.0,
    }


def _top_error_logs(db, service: str, start: datetime, end: datetime,
                    slow_ms: float, limit: int = 3):
    """Most frequent error logs, plus warnings that were also abnormally slow."""
    return list(db["log_entries"].aggregate([
        {"$match": {"service_name": service, "timestamp": {"$gte": start, "$lt": end},
                    "$or": [{"log_level": "ERROR"},
                            {"log_level": "WARNING", "response_time_ms": {"$gte": slow_ms}}]}},
        {"$group": {
            "_id": {"message": "$message", "endpoint": "$endpoint", "status": "$status_code"},
            "count": {"$sum": 1},
            "first_seen": {"$min": "$timestamp"},
            "example_id": {"$first": "$_id"},
        }},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]))


def collect_incident(db, seed: Dict[str, Any]) -> Dict[str, Any]:
    """Gather the anomalies, metrics, logs and evidence around a seed anomaly."""
    span_start = seed["window_start"] - timedelta(minutes=CORRELATION_MINUTES)
    span_end = seed["window_end"] + timedelta(minutes=CORRELATION_MINUTES)
    evidence = EvidenceLog()

    anomalies = list(db["anomaly_results"].find(
        {"is_anomaly": True, "window_start": {"$gte": span_start, "$lt": span_end}},
        sort=[("window_start", 1)],
    ))
    if not any(a["_id"] == seed["_id"] for a in anomalies):
        anomalies.insert(0, seed)

    by_service: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for anomaly in anomalies:
        by_service[anomaly["service_name"]].append(anomaly)

    services = {}
    timeline = []
    for service, service_anomalies in by_service.items():
        baseline = _baseline(db, service, span_start)
        incident_start = min(a["window_start"] for a in service_anomalies)
        incident_end = max(a["window_end"] for a in service_anomalies)
        onset = _find_onset(_minute_series(db, service, span_start, span_end), baseline)
        # Measure from when the service started degrading, not just the flagged window
        affected_start = min(onset["time"], incident_start) if onset else incident_start
        metrics = _service_metrics(db, service, affected_start, incident_end)

        rule_counts = Counter(
            rule for a in service_anomalies for rule in a.get("rule_violations", [])
        )
        signals = sorted({SIGNAL_BY_RULE.get(rule, "pattern") for rule in rule_counts}) or ["pattern"]
        max_confidence = max(a.get("confidence", 0.0) for a in service_anomalies)
        first = service_anomalies[0]

        anomaly_evidence = evidence.add(
            "anomaly", service,
            f"{len(service_anomalies)} anomalous window(s) from {_fmt(incident_start)} to "
            f"{_fmt(incident_end)}, max confidence {max_confidence:.2f}, rules: "
            f"{', '.join(f'{r} x{c}' for r, c in rule_counts.most_common()) or 'none (model only)'}",
            {"collection": "anomaly_results", "ids": [str(a["_id"]) for a in service_anomalies]},
            incident_start,
        )

        metric_evidence = None
        if metrics and baseline:
            metric_evidence = evidence.add(
                "metric", service,
                f"From {_fmt(affected_start)} to {_fmt(incident_end)}: {metrics['requests']} requests, error rate "
                f"{metrics['error_rate']:.1%} (baseline {baseline['error_rate']:.1%}), avg latency "
                f"{metrics['avg_response_time_ms']:.0f} ms (baseline {baseline['avg_response_time_ms']:.0f} ms), "
                f"p95 {metrics['p95_response_time_ms']:.0f} ms (baseline {baseline['p95_response_time_ms']:.0f} ms)",
                {"collection": "log_entries + window_features", "service_name": service,
                 "from": affected_start, "to": incident_end},
                affected_start,
            )

        onset_evidence = None
        if onset:
            value = f"{onset['value']:.0%} errors" if onset["signal"] == "errors" else f"{onset['value']:.0f} ms average latency"
            onset_evidence = evidence.add(
                "metric", service,
                f"First abnormal minute at {_fmt(onset['time'])}: {value}",
                {"collection": "log_entries", "service_name": service, "minute": onset["time"]},
                onset["time"],
            )

        log_evidence = []
        slow_ms = 3 * (baseline.get("avg_response_time_ms") or 300.0)
        top_logs = _top_error_logs(db, service, affected_start, incident_end, slow_ms)
        for log in top_logs:
            log_evidence.append(evidence.add(
                "log", service,
                f"{log['count']}x \"{log['_id']['message']}\" on {log['_id']['endpoint']} "
                f"(status {log['_id']['status']}), first at {_fmt(log['first_seen'])}",
                {"collection": "log_entries", "example_id": str(log["example_id"])},
                log["first_seen"],
            ))

        services[service] = {
            "service": service,
            "onset": onset["time"] if onset else incident_start,
            "onset_signal": onset["signal"] if onset else signals[0],
            "first_anomaly": incident_start,
            "anomaly_count": len(service_anomalies),
            "max_confidence": _round(max_confidence),
            "signals": signals,
            "rules": dict(rule_counts),
            "metrics": {k: _round(v) for k, v in metrics.items()},
            "baseline": {k: _round(v) for k, v in baseline.items() if k != "_id"},
            "top_error_logs": [
                {"message": log["_id"]["message"], "endpoint": log["_id"]["endpoint"],
                 "status": log["_id"]["status"], "count": log["count"]} for log in top_logs
            ],
            "evidence": {
                "anomaly": anomaly_evidence,
                "metrics": metric_evidence,
                "onset": onset_evidence,
                "logs": log_evidence,
            },
        }

        if onset:
            timeline.append({"time": onset["time"], "service": service,
                             "event": f"{service} starts to degrade ({onset['signal']})",
                             "evidence": [onset_evidence]})
        timeline.append({"time": incident_start, "service": service,
                         "event": f"First anomaly detected in {service} ({first.get('detection_method')})",
                         "evidence": [anomaly_evidence]})
        for log, log_id in zip(top_logs, log_evidence):
            timeline.append({"time": log["first_seen"], "service": service,
                             "event": f"First \"{log['_id']['message']}\" log",
                             "evidence": [log_id]})

    timeline.sort(key=lambda item: item["time"])
    return {
        "span": {"start": span_start, "end": span_end},
        "services": services,
        "timeline": timeline,
        "evidence": evidence,
    }


def rank_hypotheses(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Score root-cause candidates using timing, dependencies and log messages."""
    services = incident["services"]
    ordered = sorted(services.values(), key=lambda s: s["onset"])
    hypotheses = []

    for candidate in ordered:
        name = candidate["service"]
        dependents = [s for s in services if name in SERVICE_DEPENDENCIES.get(s, [])]
        later_dependents = [s for s in dependents if services[s]["onset"] >= candidate["onset"]]
        mentions = [
            s for s in services if s != name and any(
                name in log["message"] for log in services[s]["top_error_logs"])
        ]

        score = 0.3 * candidate["max_confidence"]
        reasons, evidence_ids = [], [candidate["evidence"]["anomaly"]]
        if candidate is ordered[0]:
            score += 0.25
            reasons.append(f"it degraded first (at {_fmt(candidate['onset'])})")
            if candidate["evidence"]["onset"]:
                evidence_ids.append(candidate["evidence"]["onset"])
        if later_dependents:
            score += 0.25 * len(later_dependents) / max(len(services) - 1, 1)
            verb = "depends" if len(later_dependents) == 1 else "depend"
            reasons.append(f"{', '.join(later_dependents)} {verb} on it and failed afterwards")
            evidence_ids += [services[s]["evidence"]["anomaly"] for s in later_dependents]
        if mentions:
            score += 0.2
            reasons.append(f"error logs of {', '.join(mentions)} mention {name}")
            evidence_ids += [e for s in mentions for e in services[s]["evidence"]["logs"]]
        if candidate["evidence"]["metrics"]:
            evidence_ids.append(candidate["evidence"]["metrics"])

        if len(services) == 1:
            title = f"Localized {', '.join(candidate['signals'])} problem in {name}"
            reasons.append("no other service was affected in the same period")
            score += 0.2
        elif later_dependents or mentions:
            title = f"Cascading failure originating in {name}"
        else:
            title = f"Independent {', '.join(candidate['signals'])} problem in {name}"

        hypotheses.append({
            "title": title,
            "service": name,
            "confidence": _round(min(score, 0.99), 2),
            "reasoning": "; ".join(reasons) or "anomalous during the incident window",
            "evidence": sorted(set(evidence_ids), key=lambda e: int(e[1:])),
        })

    hypotheses.sort(key=lambda h: h["confidence"], reverse=True)
    return hypotheses


def recommended_checks(incident: Dict[str, Any], hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Read-only troubleshooting steps derived from the evidence."""
    services = incident["services"]
    root = hypotheses[0]["service"] if hypotheses else None
    ordered = sorted(services.values(), key=lambda s: (s["service"] != root, s["onset"]))
    steps = []
    for service in ordered:
        detail = (f"\"{service['top_error_logs'][0]['message']}\" on {service['top_error_logs'][0]['endpoint']}"
                  if service["top_error_logs"] else "the failing requests")
        # A traffic drop next to errors or latency is a symptom, not a separate lead
        signals = [s for s in service["signals"] if s != "traffic"] or service["signals"]
        if service["service"] != root:
            # Downstream services: follow their main error first
            signals = signals[:1]
        for signal in signals:
            steps.append({
                "service": service["service"],
                "action": CHECKS_BY_SIGNAL[signal].format(
                    service=service["service"], detail=detail, onset=_fmt(service["onset"])),
                "evidence": [e for e in [service["evidence"]["metrics"], *service["evidence"]["logs"][:1]] if e],
                "requires_human_approval": False,
            })
    if root and len(services) > 1:
        steps.insert(1, {
            "service": root,
            "action": f"Confirm the dependency path: check whether calls from "
                      f"{', '.join(s for s in services if s != root)} to {root} time out or fail.",
            "evidence": [services[s]["evidence"]["anomaly"] for s in services],
            "requires_human_approval": False,
        })
    return steps


def severity_of(incident: Dict[str, Any]) -> str:
    services = incident["services"].values()
    critical_rules = {"very_high_error_rate"}
    if len(incident["services"]) > 1 or any(critical_rules & set(s["rules"]) for s in services):
        return "critical"
    if any(s["max_confidence"] >= 0.8 for s in services):
        return "high"
    return "medium"


def build_prompt(facts: Dict[str, Any]) -> str:
    conclusion = facts["conclusion"]
    first_evidence = conclusion["evidence"][0]
    return (
        "You are an incident investigator for a microservice platform. The analysis "
        "below was computed from the system's logs. Explain it to an engineer.\n\n"
        "STRICT RULES:\n"
        "1. End EVERY sentence with the evidence IDs that support it in square brackets, "
        f"for example: \"{conclusion['service']} degraded first [{first_evidence}].\"\n"
        "2. Use only facts, numbers and evidence IDs from the FACTS. Never invent anything.\n"
        f"3. The root cause is the CONCLUSION ({conclusion['title']}). Explain why, using "
        "its reasoning and evidence. Mention alternatives only if they are in the facts.\n"
        "4. Next steps must be specific read-only checks on a named service, each with "
        "evidence IDs. No generic advice (no monitoring plans, no recovery plans).\n"
        "5. You cannot run commands. Never tell anyone to restart, roll back, delete or "
        "change anything.\n\n"
        "Write exactly these four headings, each followed by 1-3 short sentences:\n"
        "Summary\nRoot cause\nImpact\nNext steps\n\n"
        f"FACTS:\n{json.dumps(facts, indent=1, default=str)}"
    )


def call_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate", data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with _opener.open(request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama returned {e.code}: {detail} (model '{OLLAMA_MODEL}'; check 'ollama list')")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        raise RuntimeError(f"Could not reach Ollama at {OLLAMA_URL}: {e}. Is 'ollama serve' running?")
    text = body.get("response", "").strip()
    if not text:
        raise RuntimeError("Ollama returned an empty response")
    return text


def validate_narrative(text: str, evidence_ids: set) -> Dict[str, Any]:
    """Check citations and flag destructive suggestions in the LLM output."""
    cited = set(re.findall(r"E\d+", " ".join(re.findall(r"\[([^\]]+)\]", text))))
    uncited = []
    for line in text.splitlines():
        # Drop markdown decoration (bullets, numbering, bold, headings)
        plain = re.sub(r"^[\s#>*\-\d.)]+|\*\*|__", "", line).strip()
        if not plain or plain.endswith(":") or len(plain) < 25:
            continue  # headings, labels and fragments
        for sentence in re.split(r"(?<=[.!?])\s+", plain):
            if len(sentence) >= 25 and not re.search(r"\[E\d+", sentence):
                uncited.append(sentence)
    destructive = sorted({m.group(0).lower() for m in DESTRUCTIVE_PATTERN.finditer(text)})
    return {
        "cited_evidence": sorted(cited & evidence_ids, key=lambda e: int(e[1:])),
        "unknown_citations": sorted(cited - evidence_ids),
        "uncited_statements": uncited,
        "grounded": bool(cited & evidence_ids) and not (cited - evidence_ids),
        "destructive_actions_flagged": destructive,
        "requires_human_approval": bool(destructive),
    }


def investigate(db, seed: Dict[str, Any], use_llm: bool = True) -> Dict[str, Any]:
    """Run a full investigation and return the incident report."""
    incident = collect_incident(db, seed)
    hypotheses = rank_hypotheses(incident)
    steps = recommended_checks(incident, hypotheses)
    evidence = incident["evidence"].items
    services = incident["services"]

    report = {
        "created_at": datetime.utcnow(),
        "seed_anomaly_id": str(seed["_id"]),
        "status": "open",
        "severity": severity_of(incident),
        "span": incident["span"],
        "affected_services": [
            {k: v for k, v in s.items() if k != "evidence"}
            for s in sorted(services.values(), key=lambda s: s["onset"])
        ],
        "timeline": incident["timeline"],
        "hypotheses": hypotheses,
        "recommended_steps": steps,
        "evidence": evidence,
        "service_dependencies": {s: SERVICE_DEPENDENCIES.get(s, []) for s in services},
        "safety": {
            "automatic_actions_executed": False,
            "note": "The investigator only reads data. Every step is a suggestion for an engineer.",
        },
        "llm": {"used": False, "model": OLLAMA_MODEL, "narrative": None, "error": None, "validation": None},
    }

    if use_llm:
        # Compact facts: small local models follow short prompts more reliably
        facts = {
            "severity": report["severity"],
            "conclusion": hypotheses[0] if hypotheses else None,
            "alternative_hypotheses": [
                {k: h[k] for k in ("title", "confidence", "evidence")} for h in hypotheses[1:]
            ],
            "timeline": [
                f"{_fmt(t['time'])} {t['event']} [{', '.join(t['evidence'])}]"
                for t in incident["timeline"]
            ],
            "service_dependencies": report["service_dependencies"],
            "evidence": {e["id"]: f"{e['service']}: {e['description']}" for e in evidence},
        }
        try:
            narrative = call_ollama(build_prompt(facts))
            report["llm"].update({
                "used": True,
                "narrative": narrative,
                "validation": validate_narrative(narrative, {e["id"] for e in evidence}),
            })
        except RuntimeError as e:
            report["llm"]["error"] = str(e)

    return report
