"""Built-in plugin catalog.

A `PluginType` describes:
- kind (unique id, e.g. "slack")
- category ("alerting", "siem", "enrichment", "custom")
- display metadata
- config schema (non-secret fields, exposed to UI)
- secrets schema (encrypted at rest, masked in API responses)
- supported events (list of event kinds it can subscribe to)
- capabilities: ["dispatch"] and/or ["query"]

The executor uses the `kind` to pick a handler.
"""
from __future__ import annotations

from typing import Any


PluginType = dict[str, Any]

CATALOG: list[PluginType] = [
    {
        "kind": "webhook",
        "category": "custom",
        "display_name": "Generic Webhook",
        "description": "POST a JSON payload of the event to any HTTPS endpoint. HMAC signature optional.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "url", "label": "URL", "type": "url", "required": True, "placeholder": "https://example.com/hooks/sec-master"},
            {"key": "headers", "label": "Extra Headers (JSON)", "type": "text", "required": False, "placeholder": '{"X-Custom": "value"}'},
        ],
        "secrets_schema": [
            {"key": "hmac_secret", "label": "HMAC Signing Secret (optional)", "required": False},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "slack",
        "category": "alerting",
        "display_name": "Slack",
        "description": "Post fleet events as formatted messages into a Slack channel via incoming webhook.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "channel_note", "label": "Note / Channel Name", "type": "text", "required": False, "placeholder": "#soc-alerts"},
        ],
        "secrets_schema": [
            {"key": "webhook_url", "label": "Slack Incoming Webhook URL", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "discord",
        "category": "alerting",
        "display_name": "Discord",
        "description": "Post fleet events into a Discord channel via webhook.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "username", "label": "Bot Username", "type": "text", "required": False, "placeholder": "sec-master"},
        ],
        "secrets_schema": [
            {"key": "webhook_url", "label": "Discord Webhook URL", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "pagerduty",
        "category": "alerting",
        "display_name": "PagerDuty",
        "description": "Trigger PagerDuty Events API v2 for critical fleet events.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "min_severity", "label": "Minimum CVE Severity to Page", "type": "select",
             "options": ["low", "medium", "high", "critical"], "required": False, "default": "high"},
        ],
        "secrets_schema": [
            {"key": "routing_key", "label": "Integration Routing Key", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "splunk_hec",
        "category": "siem",
        "display_name": "Splunk HEC",
        "description": "Forward every fleet event to a Splunk HTTP Event Collector.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "url", "label": "HEC Endpoint URL", "type": "url", "required": True, "placeholder": "https://splunk.example:8088/services/collector"},
            {"key": "index", "label": "Splunk Index", "type": "text", "required": False, "placeholder": "sec_master"},
            {"key": "sourcetype", "label": "Sourcetype", "type": "text", "required": False, "default": "sec_master:event"},
            {"key": "verify_tls", "label": "Verify TLS", "type": "bool", "default": True},
        ],
        "secrets_schema": [
            {"key": "hec_token", "label": "HEC Token", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "elastic",
        "category": "siem",
        "display_name": "Elasticsearch",
        "description": "Index fleet events into an Elasticsearch index.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "url", "label": "Elasticsearch URL", "type": "url", "required": True, "placeholder": "https://es.example:9200"},
            {"key": "index", "label": "Index", "type": "text", "required": True, "placeholder": "sec-master-events"},
        ],
        "secrets_schema": [
            {"key": "api_key", "label": "Base64 API Key", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
    {
        "kind": "virustotal",
        "category": "enrichment",
        "display_name": "VirusTotal",
        "description": "On-demand file hash / URL / IP reputation lookup against VirusTotal v3.",
        "capabilities": ["query"],
        "config_schema": [],
        "secrets_schema": [
            {"key": "api_key", "label": "VirusTotal API Key", "required": True},
        ],
        "supported_events": [],
        "query_schema": [
            {"key": "kind", "label": "Query kind", "type": "select", "options": ["hash", "ip", "domain"], "required": True},
            {"key": "value", "label": "Value", "type": "text", "required": True},
        ],
    },
    {
        "kind": "shodan",
        "category": "enrichment",
        "display_name": "Shodan",
        "description": "On-demand IP intelligence lookup against Shodan.",
        "capabilities": ["query"],
        "config_schema": [],
        "secrets_schema": [
            {"key": "api_key", "label": "Shodan API Key", "required": True},
        ],
        "supported_events": [],
        "query_schema": [
            {"key": "ip", "label": "IP Address", "type": "text", "required": True},
        ],
    },
    {
        "kind": "misp",
        "category": "siem",
        "display_name": "MISP",
        "description": "Push IOCs derived from fleet CVE matches into a MISP instance.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "url", "label": "MISP URL", "type": "url", "required": True, "placeholder": "https://misp.example"},
            {"key": "event_id", "label": "Target Event ID", "type": "text", "required": False},
            {"key": "verify_tls", "label": "Verify TLS", "type": "bool", "default": True},
        ],
        "secrets_schema": [
            {"key": "api_key", "label": "Automation API Key", "required": True},
        ],
        "supported_events": ["cve.matched", "manual.test"],
    },
    {
        "kind": "gotify",
        "category": "alerting",
        "display_name": "Gotify",
        "description": "Push notifications to a self-hosted Gotify server.",
        "capabilities": ["dispatch"],
        "config_schema": [
            {"key": "url", "label": "Gotify URL", "type": "url", "required": True, "placeholder": "https://gotify.example"},
            {"key": "priority", "label": "Priority (0-10)", "type": "text", "required": False, "default": "5"},
        ],
        "secrets_schema": [
            {"key": "app_token", "label": "Application Token", "required": True},
        ],
        "supported_events": ["cve.matched", "workstation.enrolled", "workstation.profile_switched", "manual.test"],
    },
]

CATALOG_BY_KIND: dict[str, PluginType] = {p["kind"]: p for p in CATALOG}


def get_type(kind: str) -> PluginType | None:
    return CATALOG_BY_KIND.get(kind)
