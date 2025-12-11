#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ACS Server with Auto Configuration by Serial Number
Features:
- Auto SetParam by Serial Number (SN)
- SN Config JSON structure with loader
- Device registry with JSON storage
- Configuration template system
- Auto unlock sequence integration (including superadmin)
- Web dashboard for control
- Optimized performance
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import textwrap
import re
import time
import json
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Final, Mapping, Optional, Tuple, Dict, List, Any
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Safe XML parsing
try:
    from defusedxml.ElementTree import fromstring as safe_fromstring
    from defusedxml.minidom import parseString as safe_parseString
except Exception:
    print("Error: defusedxml required. Install with: pip install defusedxml", file=sys.stderr)
    raise

# Import SN config loader
from sn_config_loader import (
    get_config_loader, get_device_registry,
    SetParam as SNSetParam, UnlockSequence
)

# =========================
# Constants
# =========================
SOAP_NS: Final[str] = "http://schemas.xmlsoap.org/soap/envelope/"
CWMP_URIS: Final[tuple[str, ...]] = (
    "urn:dslforum-org:cwmp-1-0",
    "urn:dslforum-org:cwmp-1-1",
    "urn:dslforum-org:cwmp-1-2"
)
NO_CHAIN_AFTER: Final[set[str]] = {"RebootResponse", "FactoryResetResponse"}
CONTENT_TYPE_XML: Final[str] = "text/xml; charset=utf-8"
SERVER_HDR: Final[str] = "ACS-AutoSN/1.0"


# =========================
# Settings
# =========================
@dataclass(slots=True)
class Settings:
    host: str = "0.0.0.0"
    port: int = 10302
    web_port: int = 8080
    endpoint: str = "/acs"
    verbose: bool = False
    use_https: bool = False
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    graceful_timeout: int = 8
    keep_alive: int = 30
    max_debug_chars: int = 8192
    max_body_bytes: int = 256 * 1024
    rate_limit_per_min: int = 0
    enable_metrics: bool = True
    enable_web_dashboard: bool = True
    auto_unlock: bool = True
    auto_superadmin: bool = True
    staged_unlock: bool = True  # Send params in stages vs all at once


# =========================
# Data Classes
# =========================
@dataclass(slots=True)
class SetParam:
    name: str
    value: str
    xtype: str = "xsd:string"


# =========================
# CLI Parser
# =========================
def parse_args() -> Settings:
    p = argparse.ArgumentParser("ACS Server with Auto SN Configuration")
    aa = p.add_argument
    aa("--host", default="0.0.0.0")
    aa("--port", type=int, default=10302)
    aa("--web-port", type=int, default=8080)
    aa("--endpoint", default="/acs")
    aa("-v", "--verbose", action="store_true")
    aa("--use-https", action="store_true")
    aa("--certfile")
    aa("--keyfile")
    aa("--graceful-timeout", type=int, default=8)
    aa("--keep-alive", type=int, default=30)
    aa("--max-body-bytes", type=int, default=256 * 1024)
    aa("--rate-limit-per-min", type=int, default=0)
    aa("--enable-metrics", action="store_true", default=True)
    aa("--disable-web-dashboard", action="store_true")
    aa("--disable-auto-unlock", action="store_true")
    aa("--disable-auto-superadmin", action="store_true")
    aa("--all-at-once", action="store_true", help="Send all params at once instead of staged")

    ns = p.parse_args()

    return Settings(
        host=ns.host,
        port=ns.port,
        web_port=ns.web_port,
        endpoint=ns.endpoint,
        verbose=ns.verbose,
        use_https=ns.use_https,
        certfile=ns.certfile,
        keyfile=ns.keyfile,
        graceful_timeout=ns.graceful_timeout,
        keep_alive=ns.keep_alive,
        max_body_bytes=ns.max_body_bytes,
        rate_limit_per_min=ns.rate_limit_per_min,
        enable_metrics=ns.enable_metrics,
        enable_web_dashboard=not ns.disable_web_dashboard,
        auto_unlock=not ns.disable_auto_unlock,
        auto_superadmin=not ns.disable_auto_superadmin,
        staged_unlock=not ns.all_at_once,
    )


# =========================
# Logging
# =========================
def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%y-%m-%d %H:%M:%S",
    )


_SENSITIVE_TAGS = re.compile(r"<(Password|Key|SharedSecret|.*Password.*)>(.*?)</\1>", re.I | re.S)


def _redact_xml_text(txt: str) -> str:
    return _SENSITIVE_TAGS.sub(lambda m: f"<{m.group(1)}>***</{m.group(1)}>", txt)


def _pretty_xml(raw: bytes, max_chars: int) -> str:
    sample = raw[: max_chars * 2]
    try:
        txt = _redact_xml_text(sample.decode(errors="ignore"))
        pretty = safe_parseString(txt).toprettyxml(indent="  ")
        pretty = "\n".join(ln for ln in pretty.splitlines() if ln.strip())
    except Exception:
        pretty = _redact_xml_text(sample.decode(errors="ignore"))
    return pretty if len(pretty) <= max_chars else pretty[:max_chars] + "\n...(truncated)..."


# =========================
# XML Helpers
# =========================
_XML_AMP = "&amp;"
_XML_LT = "&lt;"
_XML_GT = "&gt;"


def _xml_escape(s: str) -> str:
    return s.replace("&", _XML_AMP).replace("<", _XML_LT).replace(">", _XML_GT)


def _iter_all(root):
    yield from root.iter()


def _localname(tag: str) -> str:
    return tag.split('}')[-1] if '}' in tag else tag


def extract_id(xml_bytes: bytes) -> str:
    try:
        root = safe_fromstring(xml_bytes)
        for uri in CWMP_URIS:
            el = root.find(f".//{{{uri}}}ID")
            if el is not None and (el.text or '').strip():
                return el.text.strip()
        for e in _iter_all(root):
            if _localname(e.tag) == "ID" and (e.text or '').strip():
                return e.text.strip()
    except Exception:
        pass
    return "RID-0"


def extract_cpe_id(xml_bytes: bytes) -> Tuple[str, str, str, str]:
    """Extract OUI, SerialNumber, ProductClass, and full CPE ID"""
    try:
        root = safe_fromstring(xml_bytes)
        oui = sn = pclass = ""
        for e in _iter_all(root):
            ln = _localname(e.tag)
            if ln == "OUI":
                oui = (e.text or "").strip()
            elif ln == "SerialNumber":
                sn = (e.text or "").strip()
            elif ln == "ProductClass":
                pclass = (e.text or "").strip()
        base = f"{(oui or '000000')}-{(sn or 'UNKNOWN')}"
        cpe_id = f"{base}:{pclass}" if pclass else base
        return oui, sn, pclass, cpe_id
    except Exception:
        return "", "", "", "UNKNOWN"


def extract_inform_brief(xml_bytes: bytes) -> dict:
    """Extract DeviceId, EventCode[], and ParameterList"""
    out = {
        "vendor": "?", "oui": "?", "product_class": "?", "serial": "?",
        "events": [], "params": {}
    }
    try:
        root = safe_fromstring(xml_bytes)

        for dev in root.iter():
            if _localname(dev.tag) == "DeviceId":
                for c in dev:
                    ln = _localname(c.tag)
                    if ln == "Manufacturer":
                        out["vendor"] = (c.text or "").strip()
                    elif ln == "OUI":
                        out["oui"] = (c.text or "").strip()
                    elif ln == "ProductClass":
                        out["product_class"] = (c.text or "").strip()
                    elif ln == "SerialNumber":
                        out["serial"] = (c.text or "").strip()
                break

        for ev in root.iter():
            if _localname(ev.tag) == "Event":
                for es in ev:
                    if _localname(es.tag) != "EventStruct":
                        continue
                    for f in es:
                        if _localname(f.tag) == "EventCode":
                            code = (f.text or "").strip()
                            if code:
                                out["events"].append(code)
                break

        params = {}
        for pl in root.iter():
            if _localname(pl.tag) == "ParameterList":
                for pvs in pl:
                    if _localname(pvs.tag) != "ParameterValueStruct":
                        continue
                    name, val = "", ""
                    for f in pvs:
                        ln = _localname(f.tag)
                        if ln == "Name":
                            name = (f.text or "").strip()
                        elif ln == "Value":
                            val = (f.text or "")
                    if name:
                        params[name] = val
                break
        out["params"] = params
    except Exception:
        pass
    return out


def extract_spv_status(xml_bytes: bytes) -> Optional[int]:
    try:
        root = safe_fromstring(xml_bytes)
        for uri in CWMP_URIS:
            el = root.find(f".//{{{uri}}}SetParameterValuesResponse/{{{uri}}}Status")
            if el is not None and (el.text or '').strip():
                try:
                    return int(el.text.strip())
                except ValueError:
                    return None
    except Exception:
        pass
    return None


def extract_fault(xml_bytes: bytes) -> Tuple[Optional[int], Optional[str]]:
    fc = fs = None
    try:
        root = safe_fromstring(xml_bytes)
        for e in _iter_all(root):
            ln = _localname(e.tag)
            if ln == "FaultCode" and e.text and fc is None:
                try:
                    fc = int(e.text.strip())
                except:
                    pass
            elif ln == "FaultString" and e.text and fs is None:
                fs = e.text.strip()
    except Exception:
        pass
    return fc, fs


def classify_message(xml_bytes: bytes) -> Tuple[str, Optional[str]]:
    if not xml_bytes.strip():
        return ("Empty", None)
    try:
        root = safe_fromstring(xml_bytes)
        rid = extract_id(xml_bytes)
        for e in _iter_all(root):
            ln = _localname(e.tag)
            if ln == "Inform":
                return ("Inform", rid)
            if ln == "TransferComplete":
                return ("TransferComplete", rid)
            if ln.endswith("Response"):
                return (ln, rid)
            if ln == "Fault":
                return ("Fault", rid)
        return ("Other", rid)
    except Exception:
        return ("Other", None)


# =========================
# SOAP Builders
# =========================
def envelope(rid: str, inner: str) -> str:
    return (
        f'<?xml version="1.0"?>\n'
        f'<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:cwmp="{CWMP_URIS[0]}">\n'
        f'  <soap:Header>\n    <cwmp:ID soap:mustUnderstand="1">{rid}</cwmp:ID>\n  </soap:Header>\n'
        f'  <soap:Body>{inner}</soap:Body>\n</soap:Envelope>'
    )


def build_inform_response(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:InformResponse>\n      <MaxEnvelopes>1</MaxEnvelopes>\n    </cwmp:InformResponse>\n  ')


def build_set_parameter_values(rid: str, items: List[SetParam], parameter_key: str = "") -> str:
    n = len(items)
    plist = []
    for it in items:
        name = _xml_escape(it.name)
        val = _xml_escape(it.value)
        plist.append(
            "      <ParameterValueStruct>\n"
            f"        <Name>{name}</Name>\n"
            f"        <Value xsi:type=\"{it.xtype}\">{val}</Value>\n"
            "      </ParameterValueStruct>\n"
        )
    inner = (
        "\n    <cwmp:SetParameterValues>\n"
        f"      <ParameterList SOAP-ENC:arrayType=\"cwmp:ParameterValueStruct[{n}]\" "
        "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"
        f"{''.join(plist)}"
        "      </ParameterList>\n"
        f"      <ParameterKey>{_xml_escape(parameter_key)}</ParameterKey>\n"
        "    </cwmp:SetParameterValues>\n  "
    )
    return envelope(rid, inner)


def build_reboot(rid: str, command_key: str = "") -> str:
    return envelope(
        rid,
        '\n    <cwmp:Reboot>\n'
        f'      <CommandKey>{_xml_escape(command_key)}</CommandKey>\n'
        '    </cwmp:Reboot>\n  '
    )


def build_transfer_complete_response(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:TransferCompleteResponse/>\n  ')


# =========================
# Session State
# =========================
@dataclass(slots=True)
class CpeSession:
    rid_seq: int = 100
    queue: deque = field(default_factory=deque)
    serial_number: str = ""
    current_sequence_index: int = 0
    total_sequences: int = 0
    _tokens: float = 0.0
    _last_refill: float = 0.0

    def seed_from_inform(self, inbound_id: str, default: Optional[int] = None) -> None:
        if default is not None:
            self.rid_seq = int(default)
            return
        try:
            self.rid_seq = int(inbound_id)
        except ValueError:
            pass

    def next_rid(self) -> str:
        self.rid_seq = 1 if self.rid_seq >= 2_147_000_000 else self.rid_seq + 1
        return str(self.rid_seq)

    def allow(self, rate_per_min: int) -> bool:
        if rate_per_min <= 0:
            return True
        now = time.monotonic()
        if self._last_refill == 0.0:
            self._last_refill = now
            self._tokens = 1.0
        capacity = max(2, rate_per_min)
        self._tokens = min(capacity, self._tokens + (rate_per_min / 60.0) * (now - self._last_refill))
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def enqueue(self, name: str, **kwargs) -> None:
        self.queue.append((name, kwargs))

    def dequeue(self) -> Optional[Tuple[str, dict]]:
        return self.queue.popleft() if self.queue else None


# =========================
# Metrics
# =========================
class Metrics:
    def __init__(self) -> None:
        self._counters = {
            "http_requests_total": 0,
            "inform_total": 0,
            "empty_posts_total": 0,
            "rpc_sent_total": 0,
            "devices_unlocked_total": 0,
            "unlock_errors_total": 0,
            "responses_204_total": 0,
            "responses_200_total": 0,
        }

    def inc(self, key: str, n: int = 1) -> None:
        if key in self._counters:
            self._counters[key] += n

    def render_prom(self) -> str:
        return "\n".join([*(f"# TYPE {k} counter\n{k} {v}" for k, v in self._counters.items()), ""])

    def get_all(self) -> dict:
        return self._counters.copy()


# =========================
# WebSocket Manager for Dashboard
# =========================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


# =========================
# Main App Factory
# =========================
def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.sessions: Dict[str, CpeSession] = {}
        app.state.client_map: Dict[str, str] = {}
        app.state.metrics = Metrics()
        app.state.config_loader = get_config_loader()
        app.state.device_registry = get_device_registry()
        app.state.ws_manager = ConnectionManager()
        app.state.unlock_history: List[dict] = []

        logging.info("="*60)
        logging.info("ACS Server with Auto SN Configuration Started")
        logging.info(f"CWMP Endpoint: {settings.endpoint}")
        logging.info(f"Auto Unlock: {settings.auto_unlock}")
        logging.info(f"Auto SuperAdmin: {settings.auto_superadmin}")
        logging.info(f"Staged Unlock: {settings.staged_unlock}")
        logging.info(f"Templates loaded: {len(app.state.config_loader.list_templates())}")
        logging.info("="*60)

        try:
            yield
        finally:
            logging.info("App shutdown complete.")

    app = FastAPI(title="ACS Auto SN Server", lifespan=lifespan)

    # =========================
    # SOAP Middleware
    # =========================
    @app.middleware("http")
    async def soap_headers(req: Request, call_next):
        app.state.metrics.inc("http_requests_total")
        res = await call_next(req)

        if req.url.path == settings.endpoint and res.status_code != 204:
            h = res.headers
            h.setdefault("Content-Type", CONTENT_TYPE_XML)
            h.setdefault("SOAPAction", '""')
            h.setdefault("Server", SERVER_HDR)
            h.setdefault("Cache-Control", "no-store")

        if res.status_code == 204:
            app.state.metrics.inc("responses_204_total")
        elif 200 <= res.status_code < 300:
            app.state.metrics.inc("responses_200_total")

        return res

    # =========================
    # Helper Functions
    # =========================
    def convert_sn_params(sn_params: List[SNSetParam]) -> List[SetParam]:
        """Convert SNSetParam to SetParam"""
        return [SetParam(name=p.name, value=p.value, xtype=p.xtype) for p in sn_params]

    def enqueue_unlock_for_sn(sess: CpeSession, serial_number: str):
        """Enqueue unlock sequences for a serial number"""
        loader = app.state.config_loader
        registry = app.state.device_registry

        if settings.staged_unlock:
            sequences = loader.get_unlock_sequences_for_sn(serial_number)
            sess.total_sequences = len(sequences)
            sess.current_sequence_index = 0

            for i, seq in enumerate(sequences):
                params = convert_sn_params(seq.params)
                sess.enqueue("SetParameterValues",
                            items=params,
                            parameter_key=seq.name,
                            sequence_index=i,
                            sequence_name=seq.name)

            registry.update_device(serial_number, status="unlocking", unlock_progress=0)
            logging.info(f"Enqueued {len(sequences)} unlock sequences for SN={serial_number}")
        else:
            all_params = loader.get_all_params_for_sn(serial_number)
            if all_params:
                params = convert_sn_params(all_params)
                sess.enqueue("SetParameterValues", items=params, parameter_key="AutoUnlock")
                registry.update_device(serial_number, status="unlocking", unlock_progress=0)
                logging.info(f"Enqueued {len(params)} params (all at once) for SN={serial_number}")

    def build_rpc(name: str, rid: str, kw: dict) -> str:
        if name == "SetParameterValues":
            return build_set_parameter_values(rid, kw.get("items", []), kw.get("parameter_key", ""))
        if name == "Reboot":
            return build_reboot(rid, kw.get("command_key", ""))
        return ""

    def chain_or_204(cpe_id: Optional[str], rate: int) -> Response:
        if not cpe_id:
            return Response(status_code=204)

        sess = app.state.sessions.setdefault(cpe_id, CpeSession())
        if sess.queue and sess.allow(rate):
            item = sess.dequeue()
            if item:
                name, kw = item
                rid = sess.next_rid()
                xml = build_rpc(name, rid, kw)
                app.state.metrics.inc("rpc_sent_total")

                if settings.verbose:
                    logging.debug(f"Chaining {name} (RID={rid}) to {cpe_id}")

                return Response(content=xml, media_type="text/xml")

        return Response(status_code=204)

    def _conn_key(req: Request) -> str:
        return f"{req.client.host}:{req.client.port}" if req.client else "?:?"

    async def notify_clients(event_type: str, data: dict):
        """Broadcast event to WebSocket clients"""
        await app.state.ws_manager.broadcast({
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "data": data
        })

    # =========================
    # Health & Metrics Endpoints
    # =========================
    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"ok": True, "service": "ACS-AutoSN"})

    @app.get("/metrics")
    async def metrics():
        if not settings.enable_metrics:
            return PlainTextResponse("metrics disabled\n", status_code=404)
        return PlainTextResponse(app.state.metrics.render_prom(), media_type="text/plain")

    # =========================
    # Main CWMP Endpoint
    # =========================
    @app.post(settings.endpoint)
    async def tr069(req: Request):
        body = await req.body()

        if len(body) > settings.max_body_bytes:
            logging.warning(f"Request body too large: {len(body)} > {settings.max_body_bytes}")
            return Response(status_code=413)

        if settings.verbose and body:
            logging.debug(f"Received:\n{_pretty_xml(body, settings.max_debug_chars)}")

        kind, cwmp_id = classify_message(body)
        conn = _conn_key(req)
        cpe_id = app.state.client_map.get(conn)

        # Empty POST - chain next command
        if kind == "Empty":
            app.state.metrics.inc("empty_posts_total")
            return chain_or_204(cpe_id, settings.rate_limit_per_min)

        # Inform - device connecting
        if kind == "Inform":
            app.state.metrics.inc("inform_total")
            rid_in = cwmp_id or "RID-0"
            oui, sn, pclass, cpe_id = extract_cpe_id(body)
            brief = extract_inform_brief(body)

            # Update client map
            app.state.client_map[conn] = cpe_id

            # Get or create session
            sess = app.state.sessions.setdefault(cpe_id, CpeSession())
            sess.seed_from_inform(rid_in)
            sess.serial_number = sn

            # Extract device info
            P = brief["params"]
            vendor = brief["vendor"]
            events = ", ".join(brief["events"]) or "?"
            sw = P.get("InternetGatewayDevice.DeviceInfo.SoftwareVersion", "?")
            hw = P.get("InternetGatewayDevice.DeviceInfo.HardwareVersion", "?")
            wan_ip = P.get("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", "?")
            mac = P.get("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress", "?")
            cr_url = P.get("InternetGatewayDevice.ManagementServer.ConnectionRequestURL", "?")

            # Log device info
            logging.info(
                f"Inform from {oui}-{sn}:{pclass} (events={events})\n"
                f"  - Vendor: {vendor} | SW: {sw} | HW: {hw}\n"
                f"  - WAN IP: {wan_ip} | MAC: {mac}"
            )

            # Update device registry
            registry = app.state.device_registry
            registry.update_device(
                serial_number=sn,
                oui=oui,
                product_class=pclass,
                vendor=vendor,
                software_version=sw,
                hardware_version=hw,
                wan_ip=wan_ip,
                mac_address=mac,
                connection_url=cr_url,
                status="online"
            )
            registry.add_event(sn, f"Inform received: {events}")

            # Auto unlock if enabled
            if settings.auto_unlock:
                config = app.state.config_loader.get_config_for_sn(sn)
                if config.enabled:
                    enqueue_unlock_for_sn(sess, sn)
                    logging.info(f"Auto-unlock enabled for SN={sn} using template={config.template_name}")
                else:
                    logging.info(f"Auto-unlock disabled for SN={sn}")

            # Notify WebSocket clients
            asyncio.create_task(notify_clients("device_inform", {
                "serial_number": sn,
                "oui": oui,
                "product_class": pclass,
                "vendor": vendor,
                "events": brief["events"],
                "wan_ip": wan_ip
            }))

            return Response(content=build_inform_response(rid_in), media_type="text/xml")

        # SetParameterValuesResponse - unlock progress
        if kind == "SetParameterValuesResponse":
            status = extract_spv_status(body)
            logging.info(f"SetParameterValuesResponse from {cpe_id}, Status={status}")

            if cpe_id:
                sess = app.state.sessions.get(cpe_id)
                if sess and sess.serial_number:
                    sn = sess.serial_number
                    registry = app.state.device_registry

                    # Update progress
                    if sess.total_sequences > 0:
                        sess.current_sequence_index += 1
                        progress = int((sess.current_sequence_index / sess.total_sequences) * 100)
                        registry.update_device(sn, unlock_progress=progress)

                        if sess.current_sequence_index >= sess.total_sequences:
                            registry.update_device(sn, status="unlocked", config_applied=True, unlock_progress=100)
                            registry.add_event(sn, "Unlock completed successfully")
                            app.state.metrics.inc("devices_unlocked_total")
                            logging.info(f"Device {sn} unlock completed!")

                            # Notify clients
                            asyncio.create_task(notify_clients("device_unlocked", {
                                "serial_number": sn,
                                "success": True
                            }))
                        else:
                            registry.add_event(sn, f"Unlock progress: {progress}%")
                    else:
                        registry.update_device(sn, status="unlocked", config_applied=True, unlock_progress=100)
                        app.state.metrics.inc("devices_unlocked_total")

            return chain_or_204(cpe_id, settings.rate_limit_per_min)

        # Fault response
        if kind == "Fault":
            fc, fs = extract_fault(body)
            logging.warning(f"SOAP Fault from {cpe_id}: Code={fc}, String={fs}")

            if cpe_id:
                sess = app.state.sessions.get(cpe_id)
                if sess and sess.serial_number:
                    registry = app.state.device_registry
                    registry.update_device(sess.serial_number, status="error")
                    registry.add_event(sess.serial_number, f"Error: {fs} (code={fc})")
                    app.state.metrics.inc("unlock_errors_total")

            return Response(status_code=204)

        # TransferComplete
        if kind == "TransferComplete":
            logging.info(f"TransferComplete from {cpe_id}")
            return Response(content=build_transfer_complete_response(cwmp_id or "0"), media_type="text/xml")

        # Other responses - chain next
        if kind and kind.endswith("Response"):
            return chain_or_204(cpe_id, settings.rate_limit_per_min)

        return Response(status_code=204)

    # =========================
    # Dashboard API Endpoints
    # =========================
    @app.get("/api/devices")
    async def api_get_devices():
        """Get all devices from registry"""
        registry = app.state.device_registry
        devices = []
        for sn, info in registry.get_all_devices().items():
            devices.append({
                "serial_number": sn,
                "oui": info.oui,
                "product_class": info.product_class,
                "vendor": info.vendor,
                "software_version": info.software_version,
                "hardware_version": info.hardware_version,
                "wan_ip": info.wan_ip,
                "mac_address": info.mac_address,
                "status": info.status,
                "unlock_progress": info.unlock_progress,
                "config_applied": info.config_applied,
                "first_seen": info.first_seen,
                "last_seen": info.last_seen,
                "events": info.events[-20:]
            })
        return JSONResponse({"devices": devices, "total": len(devices)})

    @app.get("/api/devices/{serial_number}")
    async def api_get_device(serial_number: str):
        """Get specific device"""
        registry = app.state.device_registry
        info = registry.get_device(serial_number)
        if not info:
            return JSONResponse({"error": "Device not found"}, status_code=404)
        return JSONResponse({
            "serial_number": serial_number,
            "oui": info.oui,
            "product_class": info.product_class,
            "vendor": info.vendor,
            "software_version": info.software_version,
            "hardware_version": info.hardware_version,
            "wan_ip": info.wan_ip,
            "mac_address": info.mac_address,
            "status": info.status,
            "unlock_progress": info.unlock_progress,
            "config_applied": info.config_applied,
            "first_seen": info.first_seen,
            "last_seen": info.last_seen,
            "events": info.events
        })

    @app.delete("/api/devices/{serial_number}")
    async def api_delete_device(serial_number: str):
        """Delete device from registry"""
        registry = app.state.device_registry
        registry.delete_device(serial_number)
        return JSONResponse({"success": True})

    @app.get("/api/templates")
    async def api_get_templates():
        """Get all available templates"""
        loader = app.state.config_loader
        templates = []
        for name in loader.list_templates():
            tpl = loader._templates.get(name)
            if tpl:
                templates.append({
                    "name": name,
                    "description": tpl.description,
                    "sequences": len(tpl.sequences),
                    "superadmin_enabled": tpl.superadmin_enabled
                })
        return JSONResponse({"templates": templates})

    @app.get("/api/config/{serial_number}")
    async def api_get_config(serial_number: str):
        """Get configuration for a serial number"""
        loader = app.state.config_loader
        config = loader.get_config_for_sn(serial_number)
        params = loader.get_all_params_for_sn(serial_number)

        return JSONResponse({
            "serial_number": serial_number,
            "template": config.template_name,
            "enabled": config.enabled,
            "params": [{"name": p.name, "value": p.value, "type": p.xtype} for p in params]
        })

    @app.post("/api/config/{serial_number}/unlock")
    async def api_trigger_unlock(serial_number: str):
        """Manually trigger unlock for a device"""
        registry = app.state.device_registry
        info = registry.get_device(serial_number)

        if not info:
            return JSONResponse({"error": "Device not found"}, status_code=404)

        # Find session
        sess = None
        for cpe_id, s in app.state.sessions.items():
            if s.serial_number == serial_number:
                sess = s
                break

        if not sess:
            return JSONResponse({"error": "Device not currently connected"}, status_code=400)

        # Clear existing queue and enqueue unlock
        sess.queue.clear()
        enqueue_unlock_for_sn(sess, serial_number)

        return JSONResponse({"success": True, "message": "Unlock queued"})

    @app.post("/api/reload")
    async def api_reload_config():
        """Reload all configurations"""
        app.state.config_loader.reload()
        return JSONResponse({
            "success": True,
            "templates": len(app.state.config_loader.list_templates())
        })

    @app.get("/api/stats")
    async def api_get_stats():
        """Get server statistics"""
        registry = app.state.device_registry
        all_devices = registry.get_all_devices()

        stats = {
            "total_devices": len(all_devices),
            "online_devices": sum(1 for d in all_devices.values() if d.status == "online"),
            "unlocked_devices": sum(1 for d in all_devices.values() if d.status == "unlocked"),
            "unlocking_devices": sum(1 for d in all_devices.values() if d.status == "unlocking"),
            "error_devices": sum(1 for d in all_devices.values() if d.status == "error"),
            "metrics": app.state.metrics.get_all(),
            "active_sessions": len(app.state.sessions),
            "templates_loaded": len(app.state.config_loader.list_templates())
        }
        return JSONResponse(stats)

    # =========================
    # WebSocket for Real-time Updates
    # =========================
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await app.state.ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            app.state.ws_manager.disconnect(websocket)

    # =========================
    # Web Dashboard
    # =========================
    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Main web dashboard"""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACS Auto-SN Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e4e4e7;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            padding: 15px 30px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 {
            font-size: 1.5rem;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        .status-badge.online { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .status-badge.offline { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-card h3 { font-size: 0.85rem; color: #9ca3af; margin-bottom: 8px; }
        .stat-card .value {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            margin: 20px 0;
            overflow: hidden;
        }
        .card-header {
            padding: 15px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-header h2 { font-size: 1.1rem; }
        .card-body { padding: 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 20px; text-align: left; }
        th { background: rgba(0,0,0,0.2); font-size: 0.8rem; text-transform: uppercase; color: #9ca3af; }
        tr { border-bottom: 1px solid rgba(255,255,255,0.05); }
        tr:hover { background: rgba(255,255,255,0.02); }
        .device-status {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .device-status.online { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .device-status.offline { background: rgba(107, 114, 128, 0.2); color: #9ca3af; }
        .device-status.unlocking { background: rgba(234, 179, 8, 0.2); color: #eab308; }
        .device-status.unlocked { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .device-status.error { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .progress-bar {
            width: 100px;
            height: 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
        }
        .progress-bar .fill {
            height: 100%;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            transition: width 0.3s ease;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            color: white;
        }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,212,255,0.3); }
        .btn-secondary {
            background: rgba(255,255,255,0.1);
            color: #e4e4e7;
        }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .actions { display: flex; gap: 8px; }
        .event-log {
            max-height: 300px;
            overflow-y: auto;
            padding: 15px 20px;
            font-family: monospace;
            font-size: 0.85rem;
        }
        .event-item {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .event-time { color: #9ca3af; margin-right: 10px; }
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 15px 25px;
            background: rgba(34, 197, 94, 0.9);
            color: white;
            border-radius: 8px;
            display: none;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .refresh-indicator {
            width: 8px;
            height: 8px;
            background: #22c55e;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .no-data {
            padding: 40px;
            text-align: center;
            color: #9ca3af;
        }
    </style>
</head>
<body>
    <header>
        <h1>ACS Auto-SN Dashboard</h1>
        <div style="display: flex; align-items: center; gap: 15px;">
            <span class="status-badge online" id="ws-status">
                <span class="refresh-indicator"></span>
                Connected
            </span>
            <button class="btn btn-secondary" onclick="reloadConfig()">Reload Config</button>
        </div>
    </header>

    <div class="container">
        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <h3>Total Devices</h3>
                <div class="value" id="stat-total">0</div>
            </div>
            <div class="stat-card">
                <h3>Online</h3>
                <div class="value" id="stat-online">0</div>
            </div>
            <div class="stat-card">
                <h3>Unlocked</h3>
                <div class="value" id="stat-unlocked">0</div>
            </div>
            <div class="stat-card">
                <h3>Unlocking</h3>
                <div class="value" id="stat-unlocking">0</div>
            </div>
            <div class="stat-card">
                <h3>Errors</h3>
                <div class="value" id="stat-errors">0</div>
            </div>
            <div class="stat-card">
                <h3>Templates</h3>
                <div class="value" id="stat-templates">0</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Devices</h2>
                <button class="btn btn-primary" onclick="refreshDevices()">Refresh</button>
            </div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Serial Number</th>
                            <th>Vendor</th>
                            <th>Product</th>
                            <th>WAN IP</th>
                            <th>Status</th>
                            <th>Progress</th>
                            <th>Last Seen</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="devices-table">
                        <tr><td colspan="8" class="no-data">Loading devices...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Event Log</h2>
                <button class="btn btn-secondary" onclick="clearEvents()">Clear</button>
            </div>
            <div class="card-body event-log" id="event-log">
                <div class="event-item"><span class="event-time">--:--:--</span> Waiting for events...</div>
            </div>
        </div>
    </div>

    <div class="toast" id="toast">Operation completed</div>

    <script>
        let ws;
        const events = [];

        function connectWebSocket() {
            const wsUrl = `ws://${window.location.host}/ws`;
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                document.getElementById('ws-status').className = 'status-badge online';
                document.getElementById('ws-status').innerHTML = '<span class="refresh-indicator"></span> Connected';
                addEvent('WebSocket connected');
            };

            ws.onclose = () => {
                document.getElementById('ws-status').className = 'status-badge offline';
                document.getElementById('ws-status').innerHTML = 'Disconnected';
                addEvent('WebSocket disconnected, reconnecting...');
                setTimeout(connectWebSocket, 3000);
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleEvent(data);
            };
        }

        function handleEvent(data) {
            if (data.type === 'device_inform') {
                addEvent(`Device connected: ${data.data.serial_number} (${data.data.wan_ip})`);
                refreshDevices();
                refreshStats();
            } else if (data.type === 'device_unlocked') {
                addEvent(`Device unlocked: ${data.data.serial_number}`);
                showToast('Device unlocked successfully!');
                refreshDevices();
                refreshStats();
            }
        }

        function addEvent(message) {
            const now = new Date().toLocaleTimeString();
            events.unshift({ time: now, message: message });
            if (events.length > 100) events.pop();
            renderEvents();
        }

        function renderEvents() {
            const container = document.getElementById('event-log');
            container.innerHTML = events.map(e =>
                `<div class="event-item"><span class="event-time">${e.time}</span>${e.message}</div>`
            ).join('');
        }

        function clearEvents() {
            events.length = 0;
            renderEvents();
        }

        async function refreshStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stat-total').textContent = data.total_devices;
                document.getElementById('stat-online').textContent = data.online_devices;
                document.getElementById('stat-unlocked').textContent = data.unlocked_devices;
                document.getElementById('stat-unlocking').textContent = data.unlocking_devices;
                document.getElementById('stat-errors').textContent = data.error_devices;
                document.getElementById('stat-templates').textContent = data.templates_loaded;
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }

        async function refreshDevices() {
            try {
                const res = await fetch('/api/devices');
                const data = await res.json();
                const tbody = document.getElementById('devices-table');

                if (data.devices.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="no-data">No devices connected yet</td></tr>';
                    return;
                }

                tbody.innerHTML = data.devices.map(d => `
                    <tr>
                        <td><strong>${d.serial_number}</strong></td>
                        <td>${d.vendor || '-'}</td>
                        <td>${d.product_class || '-'}</td>
                        <td>${d.wan_ip || '-'}</td>
                        <td><span class="device-status ${d.status}">${d.status}</span></td>
                        <td>
                            <div class="progress-bar">
                                <div class="fill" style="width: ${d.unlock_progress}%"></div>
                            </div>
                        </td>
                        <td>${d.last_seen ? new Date(d.last_seen).toLocaleString() : '-'}</td>
                        <td class="actions">
                            <button class="btn btn-primary" onclick="triggerUnlock('${d.serial_number}')">Unlock</button>
                            <button class="btn btn-danger" onclick="deleteDevice('${d.serial_number}')">Delete</button>
                        </td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to fetch devices:', e);
            }
        }

        async function triggerUnlock(sn) {
            try {
                const res = await fetch(`/api/config/${sn}/unlock`, { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast('Unlock triggered for ' + sn);
                    addEvent('Unlock triggered: ' + sn);
                } else {
                    showToast('Error: ' + data.error);
                }
            } catch (e) {
                showToast('Failed to trigger unlock');
            }
        }

        async function deleteDevice(sn) {
            if (!confirm('Delete device ' + sn + '?')) return;
            try {
                await fetch(`/api/devices/${sn}`, { method: 'DELETE' });
                showToast('Device deleted');
                refreshDevices();
                refreshStats();
            } catch (e) {
                showToast('Failed to delete device');
            }
        }

        async function reloadConfig() {
            try {
                const res = await fetch('/api/reload', { method: 'POST' });
                const data = await res.json();
                showToast(`Config reloaded: ${data.templates} templates`);
                refreshStats();
            } catch (e) {
                showToast('Failed to reload config');
            }
        }

        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 3000);
        }

        // Initial load
        connectWebSocket();
        refreshStats();
        refreshDevices();

        // Auto-refresh
        setInterval(refreshStats, 10000);
        setInterval(refreshDevices, 15000);
    </script>
</body>
</html>
"""
        return HTMLResponse(content=html)

    return app


# =========================
# Server Runner
# =========================
def run_server(app: FastAPI, settings: Settings) -> None:
    ssl_args = {}
    if settings.use_https:
        if not settings.certfile or not settings.keyfile:
            sys.exit("Error: --use-https requires both --certfile and --keyfile")
        ssl_args = {"ssl_certfile": settings.certfile, "ssl_keyfile": settings.keyfile}

    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,
        timeout_keep_alive=settings.keep_alive,
        timeout_graceful_shutdown=settings.graceful_timeout,
        **ssl_args,
    )
    server = uvicorn.Server(config)

    state = {"requested": False}

    def request_shutdown(tag: str) -> None:
        if not state["requested"]:
            state["requested"] = True
            server.should_exit = True
            print(f"\n[{tag}] Graceful shutdown requested...")
        else:
            print(f"[{tag}] Forcing exit now.")
            os._exit(1)

    try:
        signal.signal(signal.SIGINT, lambda *_: request_shutdown("SIGINT"))
        signal.signal(signal.SIGTERM, lambda *_: request_shutdown("SIGTERM"))
    except Exception as e:
        logging.debug(f"Signal install failed: {e}")

    try:
        server.run()
    except KeyboardInterrupt:
        request_shutdown("KeyboardInterrupt")


# =========================
# Main Entry Point
# =========================
if __name__ == "__main__":
    settings = parse_args()
    setup_logging(settings.verbose)
    app = create_app(settings)
    run_server(app, settings)
