#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse, asyncio, logging, os, signal, sys, textwrap, re, time, json, csv, datetime
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Final, Mapping, Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response, PlainTextResponse, JSONResponse
import httpx

# --- Safe XML ---
try:
    from defusedxml.ElementTree import fromstring as safe_fromstring
    from defusedxml.minidom import parseString as safe_parseString
except Exception:
    print("Error: defusedxml is required. Install with: pip install defusedxml", file=sys.stderr)
    raise

# =========================
# Settings / Args
# =========================
@dataclass(slots=True)
class Settings:
    host: str = "0.0.0.0"
    port: int = 10302
    endpoint: str = "/acs"
    verbose: bool = False
    use_https: bool = False
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    graceful_timeout: int = 8
    keep_alive: int = 30
    max_debug_chars: int = 8192
    send_get_methods: bool = False
    rid_seed: Optional[int] = None
    max_body_bytes: int = 256 * 1024
    rate_limit_per_min: int = 0   # default off
    enable_metrics: bool = True
    accept_any_soapaction: bool = True
    send_get_params_name: Optional[str] = None
    set_params: list["SetParam"] = field(default_factory=list)
    gpn_next_level: int = 1
    gpv_batch_size: int = 128
    set_key: str = ""
    get_values: list[str] = field(default_factory=list)
    auto_get_from_names: bool = False
    get_attrs: list[str] = field(default_factory=list)
    reboot: bool = False
    reboot_key: str = ""
    factory_reset: bool = False
    download_url: Optional[str] = None
    download_type: str = "1 Firmware Upgrade Image"
    upload_url: Optional[str] = None
    upload_type: str = "1 Vendor Configuration File"
    accept_any_body: bool = False

# Global policy
NO_CHAIN_AFTER: Final[set[str]] = {"RebootResponse", "FactoryResetResponse"}

_XML_AMP = "&amp;"; _XML_LT = "&lt;"; _XML_GT = "&gt;"
def _xml_escape(s: str) -> str:
    return (s.replace("&", _XML_AMP).replace("<", _XML_LT).replace(">", _XML_GT))

# =========================
# CLI
# =========================

def parse_args() -> Settings:
    p = argparse.ArgumentParser("ACS mock listener (prod-lean v4)")
    aa = p.add_argument
    aa("--host", default="0.0.0.0"); aa("--port", type=int, default=10302)
    aa("--endpoint", default="/acs")
    aa("-v", "--verbose", action="store_true")
    aa("--use-https", action="store_true"); aa("--certfile"); aa("--keyfile")
    aa("--graceful-timeout", type=int, default=8)
    aa("--keep-alive", type=int, default=30)
    aa("--max-debug-chars", type=int, default=8192)
    aa("--send-get-methods", action="store_true")
    aa("--rid-seed", type=int)
    aa("--max-body-bytes", type=int, default=256 * 1024)
    aa("--rate-limit-per-min", type=int, default=0)
    aa("--enable-metrics", action="store_true")
    aa("--accept-any-soapaction", action="store_true")
    aa("--send-get-params-name", help="Enqueue GetParameterNames with this ParameterPath")
    aa("--set", action="append", default=[], help='Add param: Name=Value[:xsd:type] (repeatable)')
    aa("--set-json", help='JSON file with a list of {"Name","Value","Type"} objects')
    aa("--set-key", default="", help="TR-069 ParameterKey for SetParameterValues")
    aa("--get", action="append", default=[], help="Parameter name to GetParameterValues (repeatable)")
    aa("--get-json", help="JSON file with array of parameter names")
    aa("--auto-get-from-names", action="store_true")
    aa("--gpn-next-level", type=int, choices=[0,1], default=1)
    aa("--gpv-batch-size", type=int, default=128)
    aa("--get-attr", action="append", default=[], help="Parameter name to GetParameterAttributes (repeatable)")
    aa("--reboot", action="store_true", help="Send Reboot RPC after Inform")
    aa("--reboot-key", default="", help="Optional CommandKey to include in Reboot RPC")
    aa("--factory-reset", action="store_true", help="Send FactoryReset RPC after Inform")
    aa("--download-url", help="URL for Download RPC")
    aa("--download-type", default="1 Firmware Upgrade Image", help="FileType for Download RPC")
    aa("--schedule-inform-delay", type=int, default=60, help="Delay seconds for ScheduleInform RPC")
    aa("--upload-url", help="URL to receive CPE config via Upload RPC")
    aa("--upload-type", default="1 Vendor Configuration File")
    aa("--accept-any-body", action="store_true", help="Accept any POST body (skip XML parse error handling)")

    ns = p.parse_args()

    set_params: list[SetParam] = []
    for s in ns.set:
        set_params.append(_parse_set_arg(s))
    if ns.set_json:
        set_params.extend(_load_set_json(ns.set_json))

    get_values = list(ns.get)
    if ns.get_json:
        with open(ns.get_json, "r", encoding="utf-8") as f:
            get_values += list(json.load(f))

    if ns.reboot_key and not ns.reboot:
        p.error("--reboot-key requires --reboot")

    return Settings(
        host=ns.host, port=ns.port, endpoint=ns.endpoint, verbose=ns.verbose,
        use_https=ns.use_https, certfile=ns.certfile, keyfile=ns.keyfile,
        graceful_timeout=ns.graceful_timeout, keep_alive=ns.keep_alive,
        max_debug_chars=ns.max_debug_chars, send_get_methods=ns.send_get_methods,
        rid_seed=ns.rid_seed, max_body_bytes=ns.max_body_bytes,
        rate_limit_per_min=ns.rate_limit_per_min, enable_metrics=ns.enable_metrics,
        accept_any_soapaction=ns.accept_any_soapaction,
        send_get_params_name=ns.send_get_params_name,
        gpn_next_level=ns.gpn_next_level,
        gpv_batch_size=ns.gpv_batch_size,
        set_params=set_params,
        set_key=ns.set_key,
        get_values=get_values,
        auto_get_from_names=ns.auto_get_from_names,
        get_attrs = list(ns.get_attr),
        reboot=ns.reboot,
        reboot_key=ns.reboot_key,
        factory_reset=ns.factory_reset,
        download_url=ns.download_url,
        download_type=ns.download_type,
        upload_url=ns.upload_url,
        upload_type=ns.upload_type,
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

_SENSITIVE_HEADERS: Final[set[str]] = {"authorization","cookie","set-cookie","proxy-authorization"}
_SENSITIVE_TAGS = re.compile(r"<(Password|Key|SharedSecret|.*Password.*)>(.*?)</\1>", re.I | re.S)

def _redact_headers(h: Mapping[str, str]) -> dict[str, str]:
    return {k: ("***" if k.lower() in _SENSITIVE_HEADERS else v) for k, v in h.items()}

def _format_headers(h: Mapping[str, str]) -> str:
    items = sorted(_redact_headers(h).items(), key=lambda kv: kv[0].lower())
    if not items: return "(none)"
    w = max(len(k) for k, _ in items)
    return "\n".join(f"{k:<{w}} : {v}" for k, v in items)

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
    return pretty if len(pretty) <= max_chars else pretty[:max_chars] + "\n…(truncated)…"

def log_http_debug(req: Request, body: bytes, *, max_chars: int) -> None:
    logging.debug("📥 %s %s", req.method, str(req.url))
    logging.debug("─ Headers (%d)\n%s", len(req.headers), textwrap.indent(_format_headers(req.headers), "  "))
    if not body: logging.debug("─ Body (empty)"); return
    ctype = req.headers.get("content-type", "")
    if "xml" in ctype or body.lstrip().startswith(b"<"):
        pretty = _pretty_xml(body, max_chars)
    else:
        txt = body.decode(errors="ignore"); pretty = txt if len(txt)<=max_chars else txt[:max_chars] + "\n…(truncated)…"
    logging.debug("─ Body (%s; %d bytes)\n%s", ctype or "unknown", len(body), textwrap.indent(pretty, "  "))

# =========================
# CWMP parse helpers
# =========================
SOAP_NS: Final[str] = "http://schemas.xmlsoap.org/soap/envelope/"
CWMP_URIS: Final[tuple[str,...]] = ("urn:dslforum-org:cwmp-1-0","urn:dslforum-org:cwmp-1-1","urn:dslforum-org:cwmp-1-2")

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

def extract_cpe_id(xml_bytes: bytes) -> str:
    try:
        root = safe_fromstring(xml_bytes)
        oui=sn=pclass=""
        for e in _iter_all(root):
            ln = _localname(e.tag)
            if ln=="OUI": oui=(e.text or "").strip()
            elif ln=="SerialNumber": sn=(e.text or "").strip()
            elif ln=="ProductClass": pclass=(e.text or "").strip()
        base = f"{(oui or '000000')}-{(sn or 'UNKNOWN')}"
        return f"{base}:{pclass}" if pclass else base
    except Exception:
        return "UNKNOWN"

def extract_event_code(xml_bytes: bytes) -> Optional[str]:
    try:
        root = safe_fromstring(xml_bytes)
        for e in _iter_all(root):
            if _localname(e.tag) == "EventCode" and (e.text or '').strip():
                return e.text.strip()
    except Exception:
        pass
    return None

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

def extract_fault(xml_bytes: bytes) -> tuple[Optional[int], Optional[str], Optional[str], Optional[int], Optional[str]]:
    fc = fs = spv_name = spv_fc = spv_fs = None
    try:
        root = safe_fromstring(xml_bytes)
        for e in _iter_all(root):
            ln = _localname(e.tag)
            if ln == "FaultCode" and e.text and fc is None:
                try: fc = int(e.text.strip())
                except: pass
            elif ln == "FaultString" and e.text and fs is None:
                fs = e.text.strip()
            elif ln == "ParameterName" and e.text:
                spv_name = e.text.strip()
            elif ln == "FaultCode" and e.text and fc is not None and spv_fc is None:
                try: spv_fc = int(e.text.strip())
                except: pass
            elif ln == "FaultString" and e.text and fs is not None and spv_fs is None:
                spv_fs = e.text.strip()
    except Exception:
        pass
    return fc, fs, spv_name, spv_fc, spv_fs

def extract_gpn_names(xml_bytes: bytes) -> list[str]:
    out: list[str] = []
    try:
        root = safe_fromstring(xml_bytes)
        for pis in root.iter():
            if _localname(pis.tag) != "ParameterInfoStruct":
                continue
            for c in pis:
                if _localname(c.tag) == "Name":
                    n = (c.text or "").strip()
                    if n: out.append(n)
                    break
    except Exception:
        pass
    return out

def extract_gpn_info(xml_bytes: bytes) -> list[dict]:
    """
    Return: [{"Name": str, "Writable": int}, ...]
    """
    out: list[dict] = []
    try:
        root = safe_fromstring(xml_bytes)
        for pis in root.iter():
            if _localname(pis.tag) != "ParameterInfoStruct":
                continue
            name, writable = "", 0
            for c in pis:
                ln = _localname(c.tag)
                if ln == "Name":
                    name = (c.text or "").strip()
                elif ln == "Writable":
                    writable = 1 if (c.text or "").strip() in ("1","true","True") else 0
            if name:
                out.append({"Name": name, "Writable": writable})
    except Exception:
        pass
    return out

def extract_inform_brief(xml_bytes: bytes) -> dict:
    """
    ดึง DeviceId, EventCode[], และ ParameterList เป็น dict พร้อมใช้งานใน log
    Return keys: vendor, oui, product_class, serial, events(list[str]), params(dict[str,str])
    """
    out = {
        "vendor": "?", "oui": "?", "product_class": "?", "serial": "?",
        "events": [], "params": {}
    }
    try:
        root = safe_fromstring(xml_bytes)

        # DeviceId
        for dev in root.iter():
            if _localname(dev.tag) == "DeviceId":
                for c in dev:
                    ln = _localname(c.tag)
                    if ln == "Manufacturer": out["vendor"] = (c.text or "").strip()
                    elif ln == "OUI": out["oui"] = (c.text or "").strip()
                    elif ln == "ProductClass": out["product_class"] = (c.text or "").strip()
                    elif ln == "SerialNumber": out["serial"] = (c.text or "").strip()
                break

        # Events
        for ev in root.iter():
            if _localname(ev.tag) == "Event":
                for es in ev:
                    if _localname(es.tag) != "EventStruct": continue
                    for f in es:
                        if _localname(f.tag) == "EventCode":
                            code = (f.text or "").strip()
                            if code: out["events"].append(code)
                break

        # ParameterList → dict
        params = {}
        for pl in root.iter():
            if _localname(pl.tag) == "ParameterList":
                for pvs in pl:
                    if _localname(pvs.tag) != "ParameterValueStruct": continue
                    name, val = "", ""
                    for f in pvs:
                        ln = _localname(f.tag)
                        if ln == "Name": name = (f.text or "").strip()
                        elif ln == "Value": val = (f.text or "")
                    if name:
                        params[name] = val
                break
        out["params"] = params
    except Exception:
        pass
    return out


def extract_gpv_values(xml_bytes: bytes) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    try:
        root = safe_fromstring(xml_bytes)
        XSI = "http://www.w3.org/2001/XMLSchema-instance"
        for pvs in root.iter():
            if _localname(pvs.tag) != "ParameterValueStruct":
                continue
            name, val, xtype = None, "", "xsd:string"
            for c in pvs:
                ln = _localname(c.tag)
                if ln == "Name":
                    name = (c.text or "").strip()
                elif ln == "Value":
                    val = (c.text or "").strip()
                    xtype = c.attrib.get(f"{{{XSI}}}type", xtype)
            if name:
                out.append((name, xtype, val))
    except Exception:
        pass
    return out

def extract_gpa_attrs(xml_bytes: bytes) -> list[dict]:
    out = []
    try:
        root = safe_fromstring(xml_bytes)
        for pas in root.iter():
            if _localname(pas.tag) != "ParameterAttributeStruct":
                continue
            name, notif, acl = "", 0, []
            for c in pas:
                ln = _localname(c.tag)
                if ln == "Name":
                    name = (c.text or "").strip()
                elif ln == "Notification":
                    try:
                        notif = int((c.text or "0").strip())
                    except:
                        notif = 0
                elif ln == "AccessList":
                    for s in c:
                        if _localname(s.tag) == "string":
                            v = (s.text or "").strip()
                            if v:
                                acl.append(v)
            if name:
                out.append({"Name": name, "Notification": notif, "AccessList": acl})
    except Exception:
        pass
    return out

def classify_message(xml_bytes: bytes) -> Tuple[str, Optional[str]]:
    if not xml_bytes.strip():
        return ("Empty", None)
    try:
        root = safe_fromstring(xml_bytes)
        rid = extract_id(xml_bytes)
        for e in _iter_all(root):
            ln = _localname(e.tag)
            # CPE->ACS RPCs we care about:
            if ln == "Inform": return ("Inform", rid)
            if ln == "TransferComplete": return ("TransferComplete", rid)
            if ln == "AutonomousTransferComplete": return ("TransferComplete", rid)
            # Responses (server->cpe replies)
            if ln.endswith("Response"): return (ln, rid)
            if ln == "Fault": return ("Fault", rid)
        return ("Other", rid)
    except Exception:
        return ("Other", None)


# =========================
# Data models & arg parsing for --set
# =========================
@dataclass(slots=True)
class SetParam:
    name: str
    value: str
    xtype: str  # e.g., 'xsd:string', 'xsd:int', 'xsd:boolean'

_XSD_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

def _guess_xsd_type(v: str) -> str:
    lv = v.strip().lower()
    if lv in ("true", "false", "1", "0"): return "xsd:boolean"
    if _XSD_DATE_RE.match(v): return "xsd:dateTime"
    try:
        i = int(v)
        return "xsd:unsignedInt" if i >= 0 else "xsd:int"
    except ValueError:
        pass
    return "xsd:string"

def _parse_set_arg(s: str) -> SetParam:
    if "=" not in s:
        raise ValueError(f"--set expects Name=Value[:xsd:type], got: {s}")
    name, rest = s.split("=", 1)
    if ":xsd:" in rest:
        val, xtype_tail = rest.rsplit(":xsd:", 1)
        xtype = f"xsd:{xtype_tail}"
    else:
        val, xtype = rest, _guess_xsd_type(rest)
    return SetParam(name=name.strip(), value=val, xtype=xtype)

def _load_set_json(path: str) -> list[SetParam]:
    with open(path, "r", encoding="utf-8") as f:
        arr = json.load(f)
    out: list[SetParam] = []
    for it in arr:
        n = it.get("Name") or it.get("name")
        v = it.get("Value") or it.get("value")
        t = it.get("Type") or it.get("type")
        if not n or v is None:
            raise ValueError(f"Invalid JSON item: {it}")
        if not t: t = _guess_xsd_type(str(v))
        out.append(SetParam(name=str(n), value=str(v), xtype=str(t)))
    return out

def _normalize_set_items(items: list[SetParam]) -> list[SetParam]:
    dedup: dict[str, SetParam] = {}
    for it in items:
        v = it.value.strip()
        if it.xtype == "xsd:boolean":
            lv = v.lower()
            if lv in ("1", "true"):  v = "true"
            elif lv in ("0", "false"): v = "false"
        dedup[it.name] = SetParam(name=it.name, value=v, xtype=it.xtype)
    return list(dedup.values())

# =========================
# SOAP builders
# =========================

def envelope(rid: str, inner: str) -> str:
    return (f'<?xml version="1.0"?>\n'
            f'<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:cwmp="{CWMP_URIS[0]}">\n'
            f'  <soap:Header>\n    <cwmp:ID soap:mustUnderstand="1">{rid}</cwmp:ID>\n  </soap:Header>\n'
            f'  <soap:Body>{inner}</soap:Body>\n</soap:Envelope>')

def build_inform_response(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:InformResponse>\n      <MaxEnvelopes>1</MaxEnvelopes>\n    </cwmp:InformResponse>\n  ')

def build_get_rpc_methods(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:GetRPCMethods/>\n  ')

def build_get_parameter_names(rid: str, parameter_path: str = "", next_level: bool = True) -> str:
    return envelope(rid, ( "\n    <cwmp:GetParameterNames>\n"
                           f"      <ParameterPath>{_xml_escape(parameter_path)}</ParameterPath>\n"
                           f"      <NextLevel>{'1' if next_level else '0'}</NextLevel>\n"
                           "    </cwmp:GetParameterNames>\n  "))

def build_get_parameter_values(rid: str, names: list[str]) -> str:
    n = len(names)
    inner = "".join(f'        <string xsi:type="xsd:string">{_xml_escape(s)}</string>\n' for s in names)
    return envelope(rid, (
        "\n    <cwmp:GetParameterValues>\n"
        f'      <ParameterNames SOAP-ENC:arrayType="xsd:string[{n}]" '
        'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        f"{inner}"
        "      </ParameterNames>\n"
        "    </cwmp:GetParameterValues>\n  "
    ))

def build_set_parameter_values(rid: str, items: list[SetParam], parameter_key: str = "") -> str:
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

def build_factory_reset(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:FactoryReset/>\n  ')

def build_add_object(rid: str, object_name: str, param_key: str = "") -> str:
    return envelope(rid, (
        "\n    <cwmp:AddObject>\n"
        f"      <ObjectName>{_xml_escape(object_name)}</ObjectName>\n"
        f"      <ParameterKey>{_xml_escape(param_key)}</ParameterKey>\n"
        "    </cwmp:AddObject>\n  "
    ))

def build_delete_object(rid: str, object_name: str, param_key: str = "") -> str:
    return envelope(rid, (
        "\n    <cwmp:DeleteObject>\n"
        f"      <ObjectName>{_xml_escape(object_name)}</ObjectName>\n"
        f"      <ParameterKey>{_xml_escape(param_key)}</ParameterKey>\n"
        "    </cwmp:DeleteObject>\n  "
    ))

def build_transfer_complete_response(rid: str) -> str:
    return envelope(rid, '\n    <cwmp:TransferCompleteResponse/>\n  ')

def build_download(rid: str, file_type: str, url: str, username: str = "", password: str = "", file_size: int = 0, target_file_name: str = "", delay_seconds: int = 0, success_url: str = "", failure_url: str = "", command_key: str = "") -> str:
    """
    Build a cwmp:Download SOAP body wrapped by envelope().
    - rid: cwmp ID for the SOAP header (passed to envelope)
    - command_key: important to set so ACS can match TransferComplete
    """
    cmd = _xml_escape(command_key)
    inner = (
        "\n    <cwmp:Download>\n"
        f"      <CommandKey>{cmd}</CommandKey>\n"
        f"      <FileType>{_xml_escape(file_type)}</FileType>\n"
        f"      <URL>{_xml_escape(url)}</URL>\n"
        f"      <Username>{_xml_escape(username)}</Username>\n"
        f"      <Password>{_xml_escape(password)}</Password>\n"
        f"      <FileSize>{file_size}</FileSize>\n"
        f"      <TargetFileName>{_xml_escape(target_file_name)}</TargetFileName>\n"
        f"      <DelaySeconds>{delay_seconds}</DelaySeconds>\n"
        f"      <SuccessURL>{_xml_escape(success_url)}</SuccessURL>\n"
        f"      <FailureURL>{_xml_escape(failure_url)}</FailureURL>\n"
        "    </cwmp:Download>\n  "
    )
    return envelope(rid, inner)


def build_upload(rid: str, file_type: str, url: str, username: str = "", password: str = "", command_key: str = "") -> str:
    cmd = _xml_escape(command_key)
    inner = (
        "\n    <cwmp:Upload>\n"
        f"      <CommandKey>{cmd}</CommandKey>\n"
        f"      <FileType>{_xml_escape(file_type)}</FileType>\n"
        f"      <URL>{_xml_escape(url)}</URL>\n"
        f"      <Username>{_xml_escape(username)}</Username>\n"
        f"      <Password>{_xml_escape(password)}</Password>\n"
        "    </cwmp:Upload>\n  "
    )
    return envelope(rid, inner)

def build_schedule_inform(rid: str, delay_seconds: int, command_key: str = "") -> str:
    return envelope(rid, (
        "\n    <cwmp:ScheduleInform>\n"
        f"      <DelaySeconds>{delay_seconds}</DelaySeconds>\n"
        f"      <CommandKey>{_xml_escape(command_key)}</CommandKey>\n"
        "    </cwmp:ScheduleInform>\n  "
    ))

def build_set_parameter_attributes(rid: str, attributes: list[dict], parameter_key: str = "") -> str:
    # attributes = [{"Name": "...", "NotificationChange": True/False, "Notification": 1/2, "AccessListChange": False, "AccessList": []}]
    items = []
    for it in attributes:
        items.append(
            "      <SetParameterAttributesStruct>\n"
            f"        <Name>{_xml_escape(it['Name'])}</Name>\n"
            f"        <NotificationChange>{str(it.get('NotificationChange', False)).lower()}</NotificationChange>\n"
            f"        <Notification>{it.get('Notification', 0)}</Notification>\n"
            f"        <AccessListChange>{str(it.get('AccessListChange', False)).lower()}</AccessListChange>\n"
            "        <AccessList SOAP-ENC:arrayType=\"xsd:string[0]\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\"/>\n"
            "      </SetParameterAttributesStruct>\n"
        )
    inner = (
        "\n    <cwmp:SetParameterAttributes>\n"
        f"      <ParameterList SOAP-ENC:arrayType=\"cwmp:SetParameterAttributesStruct[{len(attributes)}]\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
        f"{''.join(items)}"
        "      </ParameterList>\n"
        f"      <ParameterKey>{_xml_escape(parameter_key)}</ParameterKey>\n"
        "    </cwmp:SetParameterAttributes>\n  "
    )
    return envelope(rid, inner)

def build_get_parameter_attributes(rid: str, names: list[str]) -> str:
    n = len(names)
    inner = "".join(f'        <string>{_xml_escape(s)}</string>\n' for s in names)
    return envelope(rid, (
        "\n    <cwmp:GetParameterAttributes>\n"
        f'      <ParameterNames SOAP-ENC:arrayType="xsd:string[{n}]" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">\n'
        f"{inner}"
        "      </ParameterNames>\n"
        "    </cwmp:GetParameterAttributes>\n  "
    ))


# =========================
# Session state
# =========================
@dataclass(slots=True)
class CpeSession:
    rid_seq: int = 100
    queue: deque[Tuple[str, dict]] = field(default_factory=deque)
    _tokens: float = 0.0
    _last_refill: float = 0.0
    downloaded: bool = False

    def seed_from_inform(self, inbound_id: str, default: Optional[int]) -> None:
        if default is not None:
            self.rid_seq = int(default); return
        try:
            self.rid_seq = int(inbound_id)
        except ValueError:
            pass

    def next_rid(self) -> str:
        self.rid_seq = 1 if self.rid_seq >= 2_147_000_000 else self.rid_seq + 1
        return str(self.rid_seq)

    def allow(self, rate_per_min: int) -> bool:
        if rate_per_min <= 0: return True
        now = time.monotonic()
        if self._last_refill == 0.0:
            self._last_refill = now; self._tokens = 1.0
        capacity = max(2, rate_per_min)
        self._tokens = min(capacity, self._tokens + (rate_per_min/60.0)*(now - self._last_refill))
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0; return True
        return False

    def enqueue(self, name: str, **kwargs) -> None: self.queue.append((name, kwargs))
    def dequeue(self) -> Optional[Tuple[str, dict]]: return self.queue.popleft() if self.queue else None

# =========================
# HTTP constants & helpers
# =========================
SOAP_ACTION_VALUE: Final[str] = '""'
CONTENT_TYPE_XML: Final[str] = "text/xml; charset=utf-8"
SERVER_HDR: Final[str] = "uvicorn"

def _conn_key(req: Request) -> str:
    return f"{req.client.host}:{req.client.port}" if req.client else "?:?"

# =========================
# Metrics (minimal)
# =========================
class Metrics:
    def __init__(self) -> None:
        self._counters = {
            "http_requests_total": 0, "inform_total": 0, "empty_posts_total": 0,
            "rpc_sent_total": 0, "responses_204_total": 0, "responses_200_total": 0,
            "errors_total": 0, "body_oversize_total": 0,
            # connection request
            "connreq_sent_total": 0, "connreq_fail_total": 0,
        }
    def inc(self, key: str, n: int = 1) -> None:
        if key in self._counters: self._counters[key] += n
    def render_prom(self) -> str:
        return "\n".join([*(f"# TYPE {k} counter\n{k} {v}" for k,v in self._counters.items()), ""])

# batching GPV

def _enqueue_gpv(sess: CpeSession, names: list[str], batch: int):
    if batch<=0: sess.enqueue("GetParameterValues", names=names); return
    for i in range(0,len(names),batch):
        sess.enqueue("GetParameterValues", names=names[i:i+batch])

# =========================
# App factory
# =========================

def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.sessions: dict[str, CpeSession] = {}
        app.state.client_map: dict[str, str] = {}
        app.state.metrics = Metrics()
        app.state.param_writable_map = {}
        logging.info("Endpoint=%s", settings.endpoint)
        try: yield
        finally: logging.info("App shutdown complete.")

    app = FastAPI(lifespan=lifespan)

    @app.middleware("http")
    async def soap_headers(req: Request, call_next):
        app.state.metrics.inc("http_requests_total")

        if req.url.path == settings.endpoint and not settings.accept_any_soapaction:
            sa = req.headers.get("soapaction")
            if sa not in (None, "", '""'):
                logging.warning("Invalid SOAPAction: %r", sa)
                return PlainTextResponse("Invalid SOAPAction", status_code=400)

        res = await call_next(req)

        if req.url.path == settings.endpoint and res.status_code != 204:
            h = res.headers
            h.setdefault("Content-Type", CONTENT_TYPE_XML)
            h.setdefault("SOAPAction", SOAP_ACTION_VALUE)
            h.setdefault("Server", SERVER_HDR)
            h.setdefault("Cache-Control", "no-store")
            if settings.use_https:
                h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                h.setdefault("X-Content-Type-Options", "nosniff")

        if settings.verbose:
            logging.debug("📤 %s %s -> %s", req.method, req.url.path, res.status_code)

        if res.status_code == 204:
            app.state.metrics.inc("responses_204_total")
        elif 200 <= res.status_code < 300:
            app.state.metrics.inc("responses_200_total")
        else:
            app.state.metrics.inc("errors_total")

        return res

    @app.get("/healthz")
    async def healthz(): return JSONResponse({"ok": True})

    @app.get("/metrics")
    async def metrics():
        if not settings.enable_metrics: return PlainTextResponse("metrics disabled\n", status_code=404)
        return PlainTextResponse(app.state.metrics.render_prom(), media_type="text/plain; version=0.0.4")

    def build_rpc(name: str, rid: str, kw: dict) -> str:
        if name == "GetRPCMethods": return build_get_rpc_methods(rid)
        if name == "GetParameterNames": return build_get_parameter_names(rid, kw.get("parameter_path",""), kw.get("next_level", True))
        if name == "GetParameterValues": return build_get_parameter_values(rid, kw.get("names", []))
        if name == "SetParameterValues": return build_set_parameter_values(rid, kw.get("items", []), kw.get("parameter_key", ""))

        if name == "Reboot": return build_reboot(rid, kw.get("command_key", ""))
        if name == "FactoryReset": return build_factory_reset(rid)
        if name == "AddObject": return build_add_object(rid, kw.get("object_name",""), kw.get("parameter_key",""))
        if name == "DeleteObject": return build_delete_object(rid, kw.get("object_name",""), kw.get("parameter_key",""))
        if name == "Download": return build_download(rid, kw.get("file_type", ""), kw.get("url", ""), kw.get("username", ""), kw.get("password", ""), kw.get("file_size", 0), kw.get("target_file_name", ""), kw.get("delay_seconds", 0), kw.get("success_url", ""), kw.get("failure_url", ""), kw.get("command_key", ""))

        if name == "Upload": return build_upload(rid, kw.get("file_type", ""), kw.get("url", ""), kw.get("username",""), kw.get("password",""), kw.get("command_key", ""))
        if name == "ScheduleInform": return build_schedule_inform(rid, kw.get("delay_seconds",60), kw.get("command_key",""))
        if name == "SetParameterAttributes": return build_set_parameter_attributes(rid, kw.get("attributes", []), kw.get("parameter_key",""))
        if name == "GetParameterAttributes": return build_get_parameter_attributes(rid, kw.get("names", []))

        return build_get_rpc_methods(rid)

    def chain_or_204(cpe_id: Optional[str], rate: int) -> Response:
        if not cpe_id: return Response(status_code=204)
        sess = app.state.sessions.setdefault(cpe_id, CpeSession())
        if sess.queue and sess.allow(rate):
            name, kw = sess.dequeue()
            rid = sess.next_rid()
            xml = build_rpc(name, rid, kw)
            app.state.metrics.inc("rpc_sent_total")
            if settings.verbose:
                logging.debug("📤 Chaining %s (RID=%s) to %s:\n%s", name, rid, cpe_id, textwrap.indent(xml, "  "))
            return Response(content=xml, media_type="text/xml")
        return Response(status_code=204)

    @app.post(settings.endpoint)
    async def tr069(req: Request):
        body = await req.body()
        if len(body) > settings.max_body_bytes:
            logging.warning("request body too large: %d > %d", len(body), settings.max_body_bytes)
            app.state.metrics.inc("body_oversize_total"); return Response(status_code=413)
        if settings.verbose: log_http_debug(req, body, max_chars=settings.max_debug_chars)

        kind, cwmp_id = classify_message(body)

        conn = _conn_key(req)
        cpe_id = app.state.client_map.get(conn)

        if kind == "Empty":
            app.state.metrics.inc("empty_posts_total")
            if settings.verbose:
                logging.debug("↪ Empty POST from conn=%s (CPE=%s) — chain or 204", conn, cpe_id or "?")
            return chain_or_204(cpe_id, settings.rate_limit_per_min)

        if kind == "Inform":
            app.state.metrics.inc("inform_total")
            rid_in = cwmp_id or "RID-0"
            cpe_id = extract_cpe_id(body)
            ev = extract_event_code(body)
            conn = _conn_key(req)
            app.state.client_map[conn] = cpe_id
            sess = app.state.sessions.setdefault(cpe_id, CpeSession())
            sess.seed_from_inform(rid_in, settings.rid_seed)

            brief = extract_inform_brief(body)

            P = brief["params"]  # สั้น ๆ
            vendor = brief["vendor"]
            oui = brief["oui"]
            pc = brief["product_class"]
            sn = brief["serial"]
            events = ", ".join(brief["events"]) or "?"

            sw = P.get("InternetGatewayDevice.DeviceInfo.SoftwareVersion", "?")
            hw = P.get("InternetGatewayDevice.DeviceInfo.HardwareVersion", "?")
            spec = P.get("InternetGatewayDevice.DeviceInfo.SpecVersion", "?")
            cr_url = P.get("InternetGatewayDevice.ManagementServer.ConnectionRequestURL", "?")
            nat = P.get("InternetGatewayDevice.ManagementServer.NATDetected", "?")
            udp_cr = P.get("InternetGatewayDevice.ManagementServer.UDPConnectionRequestAddress", "?")
            wan_ip = P.get("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", "?")
            mac = P.get("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress", "?")

            # รูปแบบ multi-line อ่านง่าย (INFO แม้ไม่ใช้ -v)
            logging.info(
                "↪ Inform from %s-%s:%s (events=%s)\n"
                "  - Vendor: %s | OUI: %s | SN: %s\n"
                "  - SW: %s | HW: %s | Spec: %s\n"
                "  - ConnReqURL: %s | NAT: %s | UDP CR: %s\n"
                "  - WAN IP: %s | MAC: %s",
                oui, sn, pc, events,
                vendor, oui, sn,
                sw, hw, spec,
                cr_url, nat, udp_cr,
                wan_ip, mac,
            )

            if settings.send_get_methods:
                sess.enqueue("GetRPCMethods")
            if settings.send_get_params_name:
                sess.enqueue("GetParameterNames", parameter_path=settings.send_get_params_name, next_level=(settings.gpn_next_level == 1))
            if settings.get_values:
                _enqueue_gpv(sess, settings.get_values, settings.gpv_batch_size)
            if settings.set_params:
                normalized = _normalize_set_items(settings.set_params)
                if settings.verbose and len(normalized) != len(settings.set_params):
                    logging.debug("SetParameterValues: dedup %d -> %d (last-write-wins)",
                                  len(settings.set_params), len(normalized))
                sess.enqueue("SetParameterValues", items=normalized, parameter_key=settings.set_key)
            if settings.get_attrs:   #
                sess.enqueue("GetParameterAttributes", names=settings.get_attrs)
            if settings.reboot:
                sess.enqueue("Reboot", command_key=settings.reboot_key)
            if settings.factory_reset:
                sess.enqueue("FactoryReset")
            if settings.download_url and not getattr(sess, "downloaded", False):
                cmdkey = f"dl-{int(time.time())}"
                sess.enqueue("Download", file_type=settings.download_type,
                             url=settings.download_url, command_key=cmdkey)
                sess.downloaded = True
            if settings.upload_url:
                cmdkey = f"cfg-{int(time.time())}"
                sess.enqueue("Upload", file_type=settings.upload_type, url=settings.upload_url, command_key=cmdkey)
            if settings.verbose:
                logging.debug("↪ Inform (ID=%s, CPE=%s, event=%s, conn=%s) — reply InformResponse; next: CPE empty POST",
                              rid_in, cpe_id, ev or "-", conn)
            return Response(content=build_inform_response(rid_in), media_type="text/xml")

        if kind and kind.endswith("Response"):
            if settings.verbose:
                extra = ""
                if kind == "SetParameterValuesResponse":
                    st = extract_spv_status(body)
                    extra = f", Status={st if st is not None else '-'}"
                logging.debug("↪ %s received (CPE=%s%s) — chain next or 204", kind, cpe_id or "?", extra)

            if kind in NO_CHAIN_AFTER:
                sess = app.state.sessions.get(cpe_id or "")
                if sess: sess.queue.clear()
                return Response(status_code=204)

            if kind == "GetParameterNamesResponse":
                infos = extract_gpn_info(body)  # [{"Name":..., "Writable":0/1}, ...]
                if infos:
                    # เก็บ writable map ต่อ CPE
                    wid = cpe_id or ""
                    wmap = app.state.param_writable_map.setdefault(wid, {})
                    for i in infos:
                        wmap[i["Name"]] = i["Writable"]
                        if settings.verbose:
                            logging.debug("↪ GPN %s (writable=%s)", i["Name"], i["Writable"])

                    # ถ้าเปิด auto_get_from_names → ยิง GPV ต่อเฉพาะ leaf (ไม่ลงท้าย '.')
                    if settings.auto_get_from_names:
                        leaf_names = [i["Name"] for i in infos if not i["Name"].endswith('.')]
                        if leaf_names:
                            sess = app.state.sessions.get(cpe_id or "")
                            if sess:
                                _enqueue_gpv(sess, leaf_names, settings.gpv_batch_size)

            if kind == "GetParameterValuesResponse":
                pairs = extract_gpv_values(body)  # [(name, type, value), ...]
                if pairs:
                    # เตรียม group ตาม object (prefix ที่จบด้วย '.')
                    from collections import defaultdict
                    groups: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
                    for full, xtype, val in pairs:
                        if "." in full:
                            parent, leaf = full.rsplit(".", 1)
                            parent = parent + "."
                        else:
                            parent, leaf = "", full
                        groups[parent].append((leaf, xtype, val, full))

                    # ดึงแผนที่ writable ต่อ CPE
                    wid  = cpe_id or ""
                    wmap = app.state.param_writable_map.get(wid, {})

                    # ช่วยใส่ "" ให้สวยและรองรับ UTF-8
                    import json
                    def q(v: str) -> str:
                        return json.dumps(v, ensure_ascii=False)

                    # สร้างบรรทัดสวย ๆ
                    lines: list[str] = []
                    for parent in sorted(groups.keys()):
                        if parent:
                            lines.append(f"  - {parent}")
                        for leaf, xtype, val, full in sorted(groups[parent], key=lambda x: x[0].lower()):
                            wv = wmap.get(full, None)
                            wtxt = "true" if wv == 1 else ("false" if wv == 0 else "?")
                            if parent:
                                lines.append(f"    - {leaf} = {q(val)} ({xtype}, writable:{wtxt})")
                            else:
                                # กรณีไม่เจอ '.' เลย ก็พิมพ์แบน ๆ
                                lines.append(f"  - {leaf} = {q(val)} ({xtype}, writable:{wtxt})")
                        lines.append(f"");

                    # พิมพ์ผลลัพธ์ (INFO ตามที่ต้องการ)
                    logging.info("↪ GetParameterValuesResponse:\n%s", "\n".join(lines))


            if kind == "GetParameterAttributesResponse":
                attrs = extract_gpa_attrs(body)
                if attrs:
                    for a in attrs:
                        if settings.verbose:
                            logging.debug("↪ GPA %s : notif=%s, access=%s", a["Name"], a["Notification"], ",".join(a["AccessList"]) or "-")

            return chain_or_204(cpe_id, settings.rate_limit_per_min)

        if kind == "TransferComplete":
            # parse useful fields from body
            try:
                root = safe_fromstring(body)
                cmdkey = ""
                url = ""
                start = ""
                complete = ""
                status = None
                faultcode = None
                for e in root.iter():
                    ln = _localname(e.tag)
                    if ln == "CommandKey" and e.text: cmdkey = e.text.strip()
                    elif ln == "URL" and e.text: url = e.text.strip()
                    elif ln == "StartTime" and e.text: start = e.text.strip()
                    elif ln == "CompleteTime" and e.text: complete = e.text.strip()
                    elif ln == "Status" and e.text:
                        try: status = int(e.text.strip())
                        except: status = None
                    elif ln == "FaultCode" and e.text:
                        try: faultcode = int(e.text.strip())
                        except: faultcode = None
                logging.info("↪ TransferComplete from %s: CommandKey=%s, URL=%s, Status=%s, FaultCode=%s, Start=%s, Complete=%s",
                             cpe_id or "?", cmdkey or "-", url or "-", status if status is not None else "-", faultcode if faultcode is not None else "-", start or "-", complete or "-")
            except Exception as ex:
                logging.warning("Failed to parse TransferComplete body: %s", ex)
            # reply with TransferCompleteResponse SOAP
            return Response(content=build_transfer_complete_response(cwmp_id), media_type="text/xml")


        if kind == "Fault":
            fc, fs, spv_name, spv_fc, spv_fs = extract_fault(body)
            logging.warning("↪ SOAP Fault from CPE=%s: FaultCode=%s, FaultString=%s, Param=%s, ParamFault=%s/%s",
                            cpe_id or "?", fc, fs, spv_name, spv_fc, spv_fs)
            return Response(status_code=204)

        if settings.accept_any_body and not body.strip().startswith(b"<"):
            logging.warning("Non-XML body accepted (len=%d)", len(body))
        return chain_or_204(app.state.client_map.get(_conn_key(req)), settings.rate_limit_per_min)

        if settings.verbose: logging.debug("🟨 Non-Inform SOAP — 204")
        if settings.gpn_next_level == 0 and settings.verbose:
            logging.debug("⚠️ GPN NextLevel=0 may return a very large subtree.")
        return Response(status_code=204)

    return app

# =========================
# Runner
# =========================

def _check_ssl(certfile: str | None, keyfile: str | None) -> dict:
    if not certfile or not keyfile:
        sys.exit("Error: --use-https requires both --certfile and --keyfile")
    for path, label in ((certfile, "certfile"), (keyfile, "keyfile")):
        if not os.path.isfile(path): sys.exit(f"[SSL] {label} not found: {path}")
    return {"ssl_certfile": certfile, "ssl_keyfile": keyfile}

def run_server(app: FastAPI, settings: Settings) -> None:
    ssl_args = _check_ssl(settings.certfile, settings.keyfile) if settings.use_https else {}
    config = uvicorn.Config(
        app, host=settings.host, port=settings.port, log_config=None,
        timeout_keep_alive=settings.keep_alive,
        timeout_graceful_shutdown=settings.graceful_timeout, **ssl_args,
    )
    server = uvicorn.Server(config)
    app.state.server = server

    state = {"requested": False}
    def request_shutdown(tag: str) -> None:
        if not state["requested"]:
            state["requested"] = True; server.should_exit = True
            try: asyncio.get_event_loop().call_soon_threadsafe(lambda: None)
            except RuntimeError: pass
            print(f"\n[{tag}] graceful shutdown requested… (press again to force)")
        else:
            print(f"[{tag}] forcing exit now."); os._exit(1)

    try:
        signal.signal(signal.SIGINT,  lambda *_: request_shutdown("SIGINT"))
        signal.signal(signal.SIGTERM, lambda *_: request_shutdown("SIGTERM"))
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, lambda *_: request_shutdown("SIGBREAK"))
    except Exception as e:
        logging.debug("signal install failed: %s", e)

    try: server.run()
    except KeyboardInterrupt: request_shutdown("KeyboardInterrupt")

# =========================
# Main
# =========================
if __name__ == "__main__":
    settings = parse_args()
    setup_logging(settings.verbose)
    app = create_app(settings)
    run_server(app, settings)