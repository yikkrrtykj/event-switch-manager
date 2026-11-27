"""Bounded, receive-only terminal diagnostics for the standalone ConsoleLab.

This path is deliberately separate from the read-only experiment state machine.
It opens a serial endpoint under the same authorization/identity/lease gates,
but never calls any write path: no CR, credential, pagination byte or query is
sent.  It records bounded, redacted terminal structure for field diagnosis only.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from event_switch_manager.console.discovery import (
    PortTransportKind,
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.lease import (
    ConsoleLease,
    ConsoleLeaseManager,
    default_lease_manager,
)
from event_switch_manager.console.parser import (
    ConsolePromptParser,
    ParserEvent,
    ParserEventKind,
)
from event_switch_manager.console.redaction import redact_console_output
from event_switch_manager.console.transport import SerialParameters

from .authorization import issue_authorization
from .reporting import LabBuildMetadata
from .targets import get_target
from .transport import AuthorizedSerialTransport, LabSerialError

MAX_DURATION_SECONDS = 15.0
MAX_PASSIVE_BYTES = 64 * 1024
MAX_PASSIVE_EVENTS = 256
MAX_PASSIVE_CHUNKS = 512
MAX_PASSIVE_PREVIEW_TOTAL = 8192
_PREVIEW_CHARS = 240

_CONTROL_PREVIEW = (
    ("\x1b", "<ESC>"),
    ("\r", "<CR>"),
    ("\n", "<LF>"),
    ("\t", "<TAB>"),
    ("\b", "<BS>"),
)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_HEX_IDENTITY = re.compile(r"(?i)\b(?:[0-9a-f]{8,}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2,})\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/=_-]{16,}\b")
_SECRETISH = re.compile(r"(?i)\b(?:password|secret|username)\b\s*[:=]\s*\S+")


def _mask_preview(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Return a bounded structural preview; never return a raw transcript."""
    redacted = _ANSI.sub(" <ANSI> ", text)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "<identity>")
    redacted = _SECRETISH.sub("<REDACTED>", redacted)
    redacted = _IP.sub("<ip>", redacted)
    redacted = _MAC.sub("<mac>", redacted)
    redacted = _HEX_IDENTITY.sub("<identity>", redacted)
    redacted = _LONG_TOKEN.sub("<token>", redacted)
    for raw, visible in _CONTROL_PREVIEW:
        redacted = redacted.replace(raw, visible)
    redacted = redact_console_output(redacted)
    # Unknown non-printable content is represented, never rendered raw.
    redacted = "".join(
        character if 0x20 <= ord(character) <= 0x7E else f"<U+{ord(character):04X}>"
        for character in redacted
    )
    return redacted[:_PREVIEW_CHARS] + (
        "<truncated>" if len(redacted) > _PREVIEW_CHARS else ""
    )


class _LineRedactor:
    """Redact known identities only after a complete terminal line exists.

    A split identity is never emitted as a prefix: live publishing is held at
    the current line boundary.  The partial line is flushed only at end of the
    bounded diagnostic run, when any completed identity can be redacted.
    """

    def __init__(self, secrets: tuple[str, ...]) -> None:
        self._secrets = tuple(secret for secret in secrets if secret)
        self._max_secret = max((len(secret) for secret in self._secrets), default=0)
        self._pending = ""

    def _safe(self, text: str) -> str:
        for secret in self._secrets:
            text = re.sub(
                re.escape(secret),
                "<identity>",
                text,
                flags=re.IGNORECASE,
            )
        return _mask_preview(text)

    def feed(self, chunk: str) -> str:
        self._pending += chunk
        parts: list[str] = []
        while True:
            positions = [index for index in (
                self._pending.find("\n"), self._pending.find("\r"),
            ) if index >= 0]
            if not positions:
                break
            boundary = min(positions) + 1
            line, self._pending = self._pending[:boundary], self._pending[boundary:]
            parts.append(self._safe(line))
        if len(self._pending) > _PREVIEW_CHARS * 4:
            keep = max(self._max_secret, 1)
            held = self._pending[-keep:]
            excess = self._pending[:-keep]
            self._pending = held
            parts.append(_structure_preview(excess))
        return "".join(parts)

    def flush(self) -> str:
        if not self._pending:
            return ""
        # End-of-run/cancel may leave an incomplete line.  Never publish its
        # letters/digits: a trailing fragment could be an identity prefix.
        pending, self._pending = self._pending, ""
        return _structure_preview(pending)


def _structure_preview(text: str) -> str:
    """Prompt-context preview with no alphanumeric content at all."""
    rendered: list[str] = []
    for character in text:
        if character == "\r":
            rendered.append("<CR>")
        elif character == "\n":
            rendered.append("<LF>")
        elif character == "\t":
            rendered.append("<TAB>")
        elif character == "\b":
            rendered.append("<BS>")
        elif character == "\x1b":
            rendered.append("<ESC>")
        elif character.isalnum():
            rendered.append("x")
        elif 0x20 <= ord(character) <= 0x7E:
            rendered.append(character)
        else:
            rendered.append(f"<U+{ord(character):04X}>")
    preview = "".join(rendered)
    return preview[:_PREVIEW_CHARS] + (
        "<truncated>" if len(preview) > _PREVIEW_CHARS else ""
    )


def _identity_token(prompt: str | None, mode: str | None) -> str | None:
    if not prompt:
        return None
    material = f"{prompt}|{mode or 'unknown'}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


@dataclass
class _PassiveCleanupHandle:
    transport: AuthorizedSerialTransport
    lease: ConsoleLease
    authorization: Any

    def retry(self) -> None:
        self.transport.close()
        self.lease.release()
        self.authorization.cancel()


_PASSIVE_CLEANUP_LOCK = threading.Lock()
_RETAINED_PASSIVE_CLEANUP: _PassiveCleanupHandle | None = None


def cleanup_required() -> bool:
    with _PASSIVE_CLEANUP_LOCK:
        return _RETAINED_PASSIVE_CLEANUP is not None


def retry_cleanup() -> bool:
    """Retry only the retained passive close; never opens a session."""
    global _RETAINED_PASSIVE_CLEANUP
    with _PASSIVE_CLEANUP_LOCK:
        handle = _RETAINED_PASSIVE_CLEANUP
    if handle is None:
        return True
    try:
        handle.retry()
    except Exception:
        return False
    with _PASSIVE_CLEANUP_LOCK:
        if _RETAINED_PASSIVE_CLEANUP is handle:
            _RETAINED_PASSIVE_CLEANUP = None
    return True


def _retain_cleanup(handle: _PassiveCleanupHandle) -> None:
    global _RETAINED_PASSIVE_CLEANUP
    with _PASSIVE_CLEANUP_LOCK:
        _RETAINED_PASSIVE_CLEANUP = handle


@dataclass
class PassiveDiagnosticResult:
    status: str
    output_dir: Path
    zip_path: Path | None
    report_path: Path
    summary_path: Path
    events_path: Path
    transport_opened: bool
    bytes_written: int
    error: str | None = None
    primary_failure: dict[str, Any] | None = None
    cleanup_status: str = "NOT_ATTEMPTED"
    collision_reason: str | None = None
    duration_seconds: float = 0.0
    events: list[dict[str, Any]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)

    def export_zip(self) -> Path:
        return export_passive_zip(self)


@dataclass
class PassiveCallbacks:
    on_event: Callable[[str], None] | None = None
    on_chunk: Callable[[dict[str, Any]], None] | None = None
    on_status: Callable[[str], None] | None = None


def _select_passive_port(
    discovery: SerialDiscovery,
    requested: str,
    *,
    manual_bluetooth_binding: bool,
    requested_direction: str,
) -> SerialPortInfo:
    matches = [
        port for port in discovery.ports
        if port.port.casefold() == requested.casefold()
    ]
    if len(matches) != 1:
        raise ValueError("selected COM endpoint is not uniquely enumerated")
    port = matches[0]
    if port.duplicate_identity:
        raise ValueError("selected endpoint identity is duplicated")
    if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
        if not manual_bluetooth_binding:
            raise ValueError("Bluetooth SPP requires manual binding")
        if not port.pnp_instance_identity:
            raise ValueError("Bluetooth PnP identity is unavailable")
        if requested_direction not in {"incoming", "outgoing"}:
            raise ValueError("operator Bluetooth direction is required")
        if port.bluetooth_direction.value not in {
            "unknown", requested_direction,
        }:
            raise ValueError("operator Bluetooth direction conflicts with enumeration")
    elif port.identity_quality.value != "stable":
        raise ValueError("USB identity is not stable")
    return port


def run_passive_diagnostics(
    args: Any,
    *,
    callbacks: PassiveCallbacks | None = None,
    cancel_event: threading.Event | None = None,
    discovery_factory: Callable[[], SerialDiscovery] | None = None,
    serial_factory: Callable[[str, SerialParameters], Any] | None = None,
    lease_manager: ConsoleLeaseManager | None = None,
) -> PassiveDiagnosticResult:
    """Receive terminal bytes only; the only serial methods used are open/read/close."""
    if not bool(getattr(args, "operator_confirmed", False)):
        raise PermissionError("passive diagnostics require operator confirmation")
    if cleanup_required():
        raise PermissionError(
            "previous passive cleanup is unconfirmed; retry cleanup first",
        )
    output_root = Path(getattr(args, "output_dir", "console-lab-output"))
    target = get_target(str(args.target))
    requested_direction = str(
        getattr(args, "bluetooth_direction", "unknown"),
    )
    manual_bt = bool(getattr(args, "manual_bluetooth_binding", False))
    duration = float(getattr(args, "duration_seconds", 10.0))
    duration = min(MAX_DURATION_SECONDS, max(1.0, duration))
    enumerate_ports = discovery_factory or discover_serial_ports
    discovery = enumerate_ports()
    port = _select_passive_port(
        discovery,
        str(args.com),
        manual_bluetooth_binding=manual_bt,
        requested_direction=requested_direction,
    )
    is_bt = port.transport_kind is PortTransportKind.BLUETOOTH_SPP
    build = LabBuildMetadata.load()
    build.require_frozen()
    authorization = issue_authorization(
        target,
        com_endpoint=port.port,
        adapter_identity=port.adapter_identity,
        ttl_seconds=max(60.0, duration + 60.0),
        operator_confirmed=True,
        artifact_sha256=build.artifact_sha256,
        software_git_sha=build.software_git_sha,
        binding_mode="manual-bluetooth" if is_bt else "stable-usb",
        identity_confidence="manual-bound" if is_bt else "stable",
        bluetooth_direction=requested_direction if is_bt else None,
        enumerated_bluetooth_direction=(
            port.bluetooth_direction.value if is_bt else None
        ),
    )
    transport = AuthorizedSerialTransport(
        authorization,
        parameters=SerialParameters(),
        # transport.open() must re-enumerate immediately before opening and
        # validate the authorization against the fresh device identity.
        discovery=enumerate_ports,
        serial_factory=serial_factory,
    )
    output_dir = output_root / f"passive-{authorization.experiment_id[:12]}"
    output_dir.mkdir(parents=True, exist_ok=True)
    parser = ConsolePromptParser()
    events: list[dict[str, Any]] = []
    chunks: list[dict[str, Any]] = []
    transport_opened = False
    cleanup_status = "NOT_ATTEMPTED"
    lease = None
    sensitive_values = tuple(
        value for value in (
            port.adapter_identity,
            port.serial_number,
            port.location,
            port.bluetooth_name,
            port.pnp_instance_identity,
            port.remote_bluetooth_identity,
        ) if value
    )
    primary_failure: dict[str, Any] | None = None
    error: str | None = None
    redactor = _LineRedactor(sensitive_values)
    status = "COMPLETED"
    stream_offset = 0
    stream_bytes = 0
    last_prompt_event: dict[str, Any] | None = None
    last_chunk_preview: str | None = None
    active = threading.Event() if cancel_event is None else cancel_event
    opened_at = time.monotonic()

    def notify(message: str) -> None:
        if callbacks and callbacks.on_status:
            callbacks.on_status(message)

    try:
        manager = lease_manager or default_lease_manager()
        lease = manager.acquire(
            port.adapter_identity,
            "passive-terminal-diagnostic",
            endpoint=port.port,
        )
        authorization.authorize_open(transport)
        transport.open()
        transport_opened = True
        opened_at = time.monotonic()
        notify("passive: transport OPENED; receive-only (no bytes will be sent)")
        deadline = opened_at + duration
        while time.monotonic() < deadline and not active.is_set():
            authorization.check_active()
            if len(events) >= MAX_PASSIVE_EVENTS or len(chunks) >= MAX_PASSIVE_CHUNKS:
                status = "BOUNDED_LIMIT"
                break
            if transport.pending_data():
                chunk = transport.read_chunk(0.1)
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                chunk = transport.read_chunk(min(0.25, remaining))
            if not chunk:
                continue
            now = time.monotonic()
            length = len(chunk.encode("utf-8"))
            stream_offset += length
            stream_bytes += length
            live_preview = redactor.feed(chunk)
            chunk_record = {
                "chunk": len(chunks),
                "length": length,
                "offset_bytes": stream_offset,
                "relative_seconds": round(now - opened_at, 6),
                # Persisted previews are structural-only; live content is
                # redacted in memory and never written to the diagnostic ZIP.
                "preview": _structure_preview(chunk),
                "preview_kind": "structural",
            }
            chunks.append(chunk_record)
            last_chunk_preview = str(chunk_record["preview"])
            if callbacks and callbacks.on_chunk:
                callbacks.on_chunk(chunk_record)
            if live_preview and callbacks and callbacks.on_event:
                callbacks.on_event(f"[RX {length}b] {live_preview}")
            for event in parser.feed(chunk):
                if len(events) >= MAX_PASSIVE_EVENTS:
                    status = "BOUNDED_LIMIT"
                    break
                record = _event_record(
                    event,
                    index=len(events),
                    chunk_index=len(chunks) - 1,
                    stream_offset=stream_offset,
                    opened_at=opened_at,
                    identity=parser.last_prompt_identity,
                )
                events.append(record)
                if last_prompt_event is not None:
                    last_prompt_event["after_preview"] = _structure_preview(
                        last_chunk_preview,
                    )
                    last_prompt_event = None
                if event.kind is ParserEventKind.PROMPT:
                    last_prompt_event = record
                if callbacks and callbacks.on_event:
                    callbacks.on_event(
                        f"[PARSER {record['kind']}] {record.get('preview', '')}",
                    )
                if event.kind is ParserEventKind.AUTH_PROMPT:
                    status = "AUTH_PROMPT_OBSERVED"
                    primary_failure = {
                        "stage": "authentication",
                        "code": "auth-prompt-observed",
                    }
                    raise _PassiveStop("authentication prompt observed; no bytes sent")
                if event.kind is ParserEventKind.UNSAFE_STATE:
                    status = "UNSAFE_STATE"
                    primary_failure = {
                        "stage": "terminal",
                        "code": event.reason or "unsafe-state",
                    }
                    raise _PassiveStop("unsafe terminal state observed")
                if len(events) >= MAX_PASSIVE_EVENTS:
                    status = "BOUNDED_LIMIT"
                    break
            if status == "BOUNDED_LIMIT":
                break
            if active.is_set():
                status = "CANCELLED"
                break
            if parser.prompt_collision:
                status = "PROMPT_COLLISION"
                primary_failure = {
                    "stage": "terminal",
                    "code": "prompt-collision",
                    "collision_reason": parser.prompt_collision_reason,
                }
                break
            if parser.buffered_bytes > MAX_PASSIVE_BYTES:
                status = "BOUNDED_LIMIT"
                primary_failure = {
                    "stage": "terminal",
                    "code": "buffer-limit",
                }
                break
            if stream_offset > MAX_PASSIVE_BYTES:
                status = "BOUNDED_LIMIT"
                break
    except _PassiveStop as exc:
        error = str(exc)
    except LabSerialError as exc:
        status = "OPEN_FAILED" if not transport_opened else "READ_FAILED"
        primary_failure = {
            "stage": exc.stage,
            "code": exc.code,
            "exception_type": exc.exception_type,
            "os_error_type": exc.os_error_type,
            "winerror": exc.winerror,
            "errno": exc.errno,
        }
        error = f"{exc.stage}:{exc.code}"
    except Exception as exc:
        status = "FAILED" if transport_opened else "OPEN_FAILED"
        primary_failure = {
            "stage": "transport" if not transport_opened else "receive",
            "code": getattr(exc, "code", type(exc).__name__),
            "exception_type": type(exc).__name__,
        }
        error = f"{primary_failure['stage']}:{primary_failure['code']}"
    finally:
        tail_preview = redactor.flush()
        if tail_preview and callbacks and callbacks.on_event:
            callbacks.on_event(f"[RX tail] {tail_preview}")
        try:
            transport.close()
            if lease is not None:
                lease.release()
            authorization.cancel()
            cleanup_status = "RELEASED"
        except Exception as exc:
            cleanup_status = "CLEANUP_REQUIRED"
            primary_failure = primary_failure or {
                "stage": "cleanup",
                "code": "cleanup-failed",
                "exception_type": type(exc).__name__,
            }
            status = "CLEANUP_REQUIRED"
            if lease is not None:
                _retain_cleanup(
                    _PassiveCleanupHandle(transport, lease, authorization),
                )
        duration_actual = round(time.monotonic() - opened_at, 6)

    preview_budget = MAX_PASSIVE_PREVIEW_TOTAL
    for item in (*chunks, *events):
        if "preview" in item:
            preview_text = str(item["preview"])
            if preview_budget <= 0:
                item["preview"] = "<preview-budget-exhausted>"
            else:
                preview_budget -= len(preview_text)
        if "before_preview" in item:
            before = str(item["before_preview"])
            if preview_budget <= 0:
                item["before_preview"] = "<preview-budget-exhausted>"
            else:
                preview_budget -= len(before)
        if "after_preview" in item and item["after_preview"] is not None:
            after = str(item["after_preview"])
            if preview_budget <= 0:
                item["after_preview"] = "<preview-budget-exhausted>"
            else:
                preview_budget -= len(after)

    report = {
        "schema": "console-lab-passive-diagnostics-v1",
        "mode": "receive-only",
        "status": status,
        "error": error,
        "transport": {
            "com_endpoint": port.port,
            "transport_kind": port.transport_kind.value,
            "bluetooth_direction": (
                port.bluetooth_direction.value if is_bt else None
            ),
            "operator_bluetooth_direction": requested_direction if is_bt else None,
            "opened": transport_opened,
            "bytes_written": 0,
            "duration_seconds": duration_actual,
            "cleanup_status": cleanup_status,
        },
        "authorization": {
            "experiment_id": authorization.experiment_id,
            "digest": authorization.digest,
            "binding_mode": authorization.binding_mode,
            "identity_confidence": authorization.identity_confidence,
        },
        "build": {
            "artifact_sha256": build.artifact_sha256,
            "git_sha": build.software_git_sha,
            "entrypoint": build.entrypoint,
        },
        "terminal": {
            "rx_chunk_count": len(chunks),
            "rx_total_bytes": stream_bytes,
            "parser_event_counts": _event_counts(events),
            "prompt_candidates": parser.prompt_candidates,
            "prompt_repeats": parser.prompt_repeats,
            "prompt_collision_reason": parser.prompt_collision_reason,
            "parser_buffer_bytes": parser.buffered_bytes,
            "bounded_limits": {
                "duration_seconds": duration,
                "max_bytes": MAX_PASSIVE_BYTES,
                "max_events": MAX_PASSIVE_EVENTS,
                "max_chunks": MAX_PASSIVE_CHUNKS,
            },
        },
        "primary_failure": primary_failure,
        "chunks": chunks,
        "events": events,
        "privacy": {
            "raw_transcript_saved": False,
            "credentials_saved": False,
            "content_is_redacted_and_bounded": True,
            "persisted_content": "structural-only",
            "preview_total_limit_chars": MAX_PASSIVE_PREVIEW_TOTAL,
        },
        "hardware_verified": False,
        "deployment_approved": False,
    }
    report_path = output_dir / "passive-report.json"
    events_path = output_dir / "passive-events.jsonl"
    summary_path = output_dir / "passive-summary.txt"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    events_path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in events),
        encoding="utf-8",
    )
    summary_lines = [
        "ConsoleLab Passive Terminal Diagnostics",
        f"status={status}",
        f"transport_opened={transport_opened}",
        "bytes_written=0",
        f"duration_seconds={duration_actual}",
        f"cleanup={cleanup_status}",
        f"rx_chunks={len(chunks)} rx_bytes={stream_bytes}",
        f"prompt_candidates={parser.prompt_candidates} "
        f"prompt_repeats={parser.prompt_repeats}",
        f"collision_reason={parser.prompt_collision_reason}",
        f"primary_failure={json.dumps(primary_failure, ensure_ascii=False)}",
        "No raw transcript, credential, or transmitted application byte is saved.",
    ]
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    checksum_path = output_dir / "SHA256SUMS.passive"
    checksum_lines = []
    for path in (report_path, events_path, summary_path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksum_lines.append(f"{digest}  {path.name}")
    checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    result = PassiveDiagnosticResult(
        status=status,
        output_dir=output_dir,
        zip_path=None,
        report_path=report_path,
        summary_path=summary_path,
        events_path=events_path,
        transport_opened=transport_opened,
        bytes_written=0,
        error=error,
        primary_failure=primary_failure,
        cleanup_status=cleanup_status,
        collision_reason=parser.prompt_collision_reason,
        duration_seconds=duration_actual,
        events=events,
        chunks=chunks,
    )
    result.zip_path = export_passive_zip(result)
    return result


class _PassiveStop(RuntimeError):
    pass


def _event_record(
    event: ParserEvent,
    *,
    index: int,
    chunk_index: int,
    stream_offset: int,
    opened_at: float,
    identity: str | None,
) -> dict[str, Any]:
    kind = event.kind.value
    preview = _structure_preview(event.output) if event.output else ""
    record: dict[str, Any] = {
        "index": index,
        "kind": kind,
        "chunk": chunk_index,
        "stream_offset": stream_offset,
        "relative_seconds": round(time.monotonic() - opened_at, 6),
        "preview": preview,
    }
    if event.prompt is not None:
        record.update({
            "prompt_identity_token": _identity_token(
                event.prompt, event.mode.value if event.mode else None,
            ),
            "prompt_mode": event.mode.value if event.mode else None,
            "prompt_candidate_index": index,
            "line_terminated": event.line_terminated,
            "before_preview": preview,
            "after_preview": None,
        })
    if event.auth_prompt is not None:
        record["auth_prompt_kind"] = event.auth_prompt.value
    if event.reason is not None:
        record["reason"] = event.reason
    return record


def _event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        kind = str(event["kind"])
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def export_passive_zip(result: PassiveDiagnosticResult) -> Path:
    if result.zip_path is not None and result.zip_path.exists():
        return result.zip_path
    zip_path = result.output_dir / f"{result.output_dir.name}-diagnostic.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in (
            result.report_path,
            result.summary_path,
            result.events_path,
            result.output_dir / "SHA256SUMS.passive",
        ):
            archive.write(path, arcname=path.name)
    result.zip_path = zip_path
    return zip_path


__all__ = [
    "MAX_DURATION_SECONDS",
    "MAX_PASSIVE_BYTES",
    "MAX_PASSIVE_EVENTS",
    "PassiveCallbacks",
    "PassiveDiagnosticResult",
    "export_passive_zip",
    "run_passive_diagnostics",
]
