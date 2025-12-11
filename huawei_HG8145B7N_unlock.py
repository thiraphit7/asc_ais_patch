#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# test3_huawei_acs_unlock3.py — Huawei-compatible ACS mock with 3 params in first SetParamValues
#
# Flow:
#   Inform → InformResponse → Empty POST → SetParam(Unlock UI+Captcha)
#   → SetParamResponse → SetParam(CarrierLock) → SetParamResponse → empty 200 OK

import http.server, ssl
from xml.etree import ElementTree as ET
from datetime import datetime

PORT = 10302
CERT_FILE = "cert.pem"
KEY_FILE  = "key.pem"

SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
CWMP_NS  = "urn:dslforum-org:cwmp-1-0"

# ───────────────────────────────────────────────
# XML builders
# ───────────────────────────────────────────────
def build_inform_response(rid):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{SOAP_ENV}" xmlns:cwmp="{CWMP_NS}">
  <soap:Header><cwmp:ID soap:mustUnderstand="1">{rid}</cwmp:ID></soap:Header>
  <soap:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body>
</soap:Envelope>""".encode("utf-8")

def build_setparam_unlock_ui(rid="102"):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{SOAP_ENV}" xmlns:cwmp="{CWMP_NS}">
  <soap:Header><cwmp:ID soap:mustUnderstand="1">{rid}</cwmp:ID></soap:Header>
  <soap:Body>
    <cwmp:SetParameterValues>
      <ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[3]"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.Captcha_enable</Name>
          <Value xsi:type="xsd:string"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">0</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.SuperAdminSecurity</Name>
          <Value xsi:type="xsd:string"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">0</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.RemoteAccess</Name>
          <Value xsi:type="xsd:string"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">1</Value>
        </ParameterValueStruct>
      </ParameterList>
      <ParameterKey>ForceUnlockUI</ParameterKey>
    </cwmp:SetParameterValues>
  </soap:Body>
</soap:Envelope>""".encode("utf-8")

def build_setparam_carrier_unlock(rid="103"):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{SOAP_ENV}" xmlns:cwmp="{CWMP_NS}">
  <soap:Header><cwmp:ID soap:mustUnderstand="1">{rid}</cwmp:ID></soap:Header>
  <soap:Body>
    <cwmp:SetParameterValues>
      <ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[1]"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.UserInterface.CarrierLocking.X_AIS_LockingEnable</Name>
          <Value xsi:type="xsd:string"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">0</Value>
        </ParameterValueStruct>
      </ParameterList>
      <ParameterKey>CarrierUnlock</ParameterKey>
    </cwmp:SetParameterValues>
  </soap:Body>
</soap:Envelope>""".encode("utf-8")

def build_empty_response(): return b""

# ───────────────────────────────────────────────
# HTTP handler
# ───────────────────────────────────────────────
class HuaweiACSHandler(http.server.BaseHTTPRequestHandler):
    sessions = {}
    def log_message(self, *a): return

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                sz = self.rfile.readline().strip()
                if not sz: continue
                n = int(sz, 16)
                if n == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(n)
                self.rfile.readline()
            return data
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _extract_id(self, xml):
        try:
            root = ET.fromstring(xml)
            for e in root.iter():
                if e.tag.endswith("ID") and e.text:
                    return e.text.strip()
        except Exception: pass
        return "100"

    def do_POST(self):
        body = self._read_body()
        ip   = self.client_address[0]
        now  = datetime.now().strftime("%H:%M:%S")

        print("="*100)
        print(f"📥 [{now}] CPE → ACS from {ip} path={self.path}")
        for k,v in self.headers.items():
            print(f"{k}: {v}")
        print("── Body ───────────────────────────────")
        print(body.decode("utf-8", errors="replace") if body.strip() else "(empty body)")
        print("────────────────────────────────────────")

        st = HuaweiACSHandler.sessions.get(ip, {"phase":"new"})
        resp = b""

        # STEP 1: Inform
        if b"<cwmp:Inform" in body:
            rid = self._extract_id(body.decode())
            print(f"[INFO] Got Inform RID={rid}")
            resp = build_inform_response(rid)
            st["phase"] = "sent_inform_response"

        # STEP 2: Empty POST → Unlock UI
        elif st["phase"] == "sent_inform_response" and not body.strip():
            print(f"[READY] Empty POST → sending SetParameterValues (UI Unlock + Captcha)")
            resp = build_setparam_unlock_ui("102")
            st["phase"] = "sent_unlock_ui"

        # STEP 3: UI unlock done → Carrier unlock
        elif st["phase"] == "sent_unlock_ui" and b"<cwmp:SetParameterValuesResponse" in body:
            print(f"[OK] UI Unlock confirmed → send CarrierLock disable")
            resp = build_setparam_carrier_unlock("103")
            st["phase"] = "sent_carrier_unlock"

        # STEP 4: Carrier unlock done → finish
        elif st["phase"] == "sent_carrier_unlock" and b"<cwmp:SetParameterValuesResponse" in body:
            print(f"[DONE] CarrierUnlock confirmed → send final empty")
            resp = build_empty_response()
            st["phase"] = "complete"

        else:
            print("[SKIP] Unrecognized state → empty 200")
            resp = build_empty_response()

        HuaweiACSHandler.sessions[ip] = st

        length = len(resp)
        print("\n📤 ACS → CPE Response")
        print("HTTP/1.1 200 OK")
        print("Server: GenieACS/1.2.9")
        print("SOAPServer: CWMP 1.0")
        print("SOAPAction:")
        if length > 0:
            print("Content-Type: text/xml; charset=utf-8")
        print(f"Content-Length: {length}")
        print("Connection: Keep-Alive")
        print("────────────────────────────────────────")
        print(resp.decode("utf-8", errors="replace") if resp else "(empty body)")
        print("────────────────────────────────────────\n")

        self.send_response(200)
        self.send_header("Server", "GenieACS/1.2.9")
        self.send_header("SOAPServer", "CWMP 1.0")
        self.send_header("SOAPAction", "")
        if length > 0:
            self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "Keep-Alive")
        self.end_headers()
        if resp:
            self.wfile.write(resp)
            self.wfile.flush()

# ───────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────
if __name__ == "__main__":
    print(f"✅ Huawei-compatible ACS started on port {PORT} (UI+Captcha+CarrierUnlock, path=/acs)")
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), HuaweiACSHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()