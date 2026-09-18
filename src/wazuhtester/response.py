"""The structured response returned by the Wazuh logtest daemon."""
from __future__ import annotations

from collections.abc import MutableMapping
from enum import Enum, auto
from typing import Any


class LogtestStatus(Enum):
    """The semantic outcome of a log processed by the Wazuh logtest daemon.

    Members:
        RuleMatch: A rule matched the log; decoding and rule application succeeded.
        Error: The daemon reported an error while processing the log.
        NoDecoder: No decoder matched the log format; the log could not be interpreted.
        NoRule: A decoder matched, but no rule was triggered.
    """

    RuleMatch = auto()
    Error = auto()
    NoDecoder = auto()
    NoRule = auto()


class LogtestResponse:
    """Parses and stores the daemon's response to a single log event.

    Every attribute below is always safe to read regardless of `status`,
    including on `LogtestStatus.Error` (where the daemon returned no
    decoder or rule data at all): each one is given a default before any
    early return, rather than only existing conditionally.

    Attributes:
        status: Whether a rule matched, only a decoder matched, or an error occurred.
        alert: Whether an alert was triggered.
        full_log: The log as reconstructed or normalized by Wazuh.
        timestamp: The timestamp Wazuh assigned to the log.
        location: The location field indicating the log's origin.
        srcip, srcport, dstip, dstport, protocol, action: Static decoder fields, if any.
        url, extra_data: Static decoder fields, used rarely.
        decoder: The name of the decoder applied to the log, if any.
        decoder_parent: The parent of the applied decoder, if any.
        rule_id: The ID of the matched rule, if any.
        rule_level: The severity level of the matched rule, if any.
        rule_description: A description of the matched rule, if any.
        rule_groups: The set of rule groups associated with the matched rule.
        rule_mitre_ids: The set of MITRE ATT&CK technique IDs associated with the matched rule.
    """

    def __init__(self, response_dict: dict[str, Any]) -> None:
        data: dict[str, Any] = response_dict.get("data", {})
        self._messages = data.get("messages", [])

        self.status: LogtestStatus
        self.alert: bool = False
        self.full_log: str = ""
        self.timestamp: str = ""
        self.location: str = ""
        self.srcip: str | None = None
        self.srcport: str | None = None
        self.dstip: str | None = None
        self.dstport: str | None = None
        self.protocol: str | None = None
        self.action: str | None = None
        self.url: str | None = None
        self.extra_data: str | None = None
        self.decoder: str | None = None
        self.decoder_parent: str | None = None
        self.rule_id: str | None = None
        self.rule_level: int | None = None
        self.rule_description: str | None = None
        self.rule_groups: set[str] = set()
        self.rule_mitre_ids: set[str] = set()
        self._flattened_fields: dict[str, Any] = {}

        if response_dict.get("error", 0) != 0:
            self.status = LogtestStatus.Error
            return

        self.alert = data.get("alert", False)

        output: dict[str, Any] = data.get("output", {})
        self.full_log = output.get("full_log", "")
        self.timestamp = output.get("timestamp", "")
        self.location = output.get("location", "")

        data_fields: dict[str, Any] = output.get("data", {})
        self._flattened_fields = self._flatten(data_fields)

        self.srcip = data_fields.get("srcip")
        self.srcport = data_fields.get("srcport")
        self.dstip = data_fields.get("dstip")
        self.dstport = data_fields.get("dstport")
        self.protocol = data_fields.get("protocol")
        self.action = data_fields.get("action")
        self.url = data_fields.get("url")
        self.extra_data = data_fields.get("extra_data")

        decoder_info: dict[str, Any] | None = output.get("decoder")
        if decoder_info is None:
            self.status = LogtestStatus.NoDecoder
            return

        self.decoder = decoder_info.get("name")
        self.decoder_parent = decoder_info.get("parent")

        rule_info: dict[str, Any] | None = output.get("rule")
        if rule_info is None:
            self.status = LogtestStatus.NoRule
            return

        self.status = LogtestStatus.RuleMatch
        self.rule_id = rule_info.get("id")
        self.rule_level = rule_info.get("level")

        description = rule_info.get("description")
        self.rule_description = ". ".join(description) if isinstance(description, list) else description

        groups = rule_info.get("groups")
        if groups:
            self.rule_groups = set(groups)

        mitre = rule_info.get("mitre")
        if mitre:
            ids = mitre.get("id", [])
            self.rule_mitre_ids = {ids} if isinstance(ids, str) else set(ids)

    @staticmethod
    def _flatten(
        dictionary: dict[str, Any] | MutableMapping[str, Any],
        parent_key: str = "",
        separator: str = ".",
    ) -> dict[str, Any]:
        """Flatten a nested dict/list structure into a dict keyed by dotted paths."""
        items: list[tuple[str, Any]] = []
        for key, value in dictionary.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key
            if isinstance(value, MutableMapping):
                if value:
                    items.extend(LogtestResponse._flatten(value, new_key, separator).items())
                else:
                    items.append((new_key, None))
            elif isinstance(value, list):
                if value:
                    for index, entry in enumerate(value):
                        items.extend(LogtestResponse._flatten({str(index): entry}, new_key, separator).items())
                else:
                    items.append((new_key, None))
            else:
                items.append((new_key, value))
        return dict(items)

    def get_dynamic_field_names(self) -> list[str]:
        """Return the list of flattened dynamic field names."""
        return list(self._flattened_fields.keys())

    def get_dynamic_field_value(self, flattened_field_name: str) -> Any | None:
        """Return a dynamic field's value by its flattened name, or None."""
        return self._flattened_fields.get(flattened_field_name)

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible representation of the response."""
        return {
            "status": self.status.name,
            "alert": self.alert,
            "full_log": self.full_log,
            "timestamp": self.timestamp,
            "location": self.location,
            "srcip": self.srcip,
            "srcport": self.srcport,
            "dstip": self.dstip,
            "dstport": self.dstport,
            "protocol": self.protocol,
            "action": self.action,
            "url": self.url,
            "extra_data": self.extra_data,
            "decoder": self.decoder,
            "decoder_parent": self.decoder_parent,
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "rule_description": self.rule_description,
            "rule_groups": sorted(self.rule_groups),
            "rule_mitre_ids": sorted(self.rule_mitre_ids),
            "dynamic_fields": dict(sorted(self._flattened_fields.items())),
            "messages": list(self._messages),
        }
