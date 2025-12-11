#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SN Config Loader - Load and manage configurations by Serial Number
"""
from __future__ import annotations

import json
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# =========================
# Configuration Paths
# =========================
BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / "config"
TEMPLATES_DIR = CONFIG_DIR / "templates"
DEVICES_DIR = CONFIG_DIR / "devices"
DATA_DIR = BASE_DIR / "data"

SN_REGISTRY_FILE = CONFIG_DIR / "sn_registry.json"
DEVICE_REGISTRY_FILE = DATA_DIR / "device_registry.json"


# =========================
# Data Classes
# =========================
@dataclass
class SetParam:
    """Parameter to set on device"""
    name: str
    value: str
    xtype: str = "xsd:string"


@dataclass
class UnlockSequence:
    """A sequence of parameters to set"""
    name: str
    description: str
    params: List[SetParam]


@dataclass
class DeviceTemplate:
    """Configuration template for devices"""
    name: str
    description: str
    version: str
    sequences: List[UnlockSequence]
    superadmin_enabled: bool = False
    superadmin_params: List[SetParam] = field(default_factory=list)
    wifi_config_enabled: bool = False
    wifi_params: List[SetParam] = field(default_factory=list)


@dataclass
class DeviceConfig:
    """Configuration for a specific device"""
    serial_number: str
    template_name: str
    template: Optional[DeviceTemplate] = None
    custom_params: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    name: str = ""
    notes: str = ""


@dataclass
class DeviceInfo:
    """Runtime information about a connected device"""
    serial_number: str
    oui: str
    product_class: str
    vendor: str
    software_version: str
    hardware_version: str
    wan_ip: str
    mac_address: str
    connection_url: str
    first_seen: str
    last_seen: str
    status: str  # "online", "offline", "unlocking", "unlocked", "error"
    unlock_progress: int  # 0-100
    config_applied: bool
    events: List[str] = field(default_factory=list)


# =========================
# Config Loader Class
# =========================
class SNConfigLoader:
    """Load and manage configurations by Serial Number"""

    def __init__(self):
        self._registry: Dict[str, Any] = {}
        self._templates: Dict[str, DeviceTemplate] = {}
        self._device_configs: Dict[str, DeviceConfig] = {}
        self._patterns: List[Dict[str, str]] = []
        self._default_template: str = "standard_unlock"
        self._ensure_dirs()
        self._load_registry()
        self._load_templates()

    def _ensure_dirs(self):
        """Ensure all required directories exist"""
        for d in [CONFIG_DIR, TEMPLATES_DIR, DEVICES_DIR, DATA_DIR]:
            d.mkdir(parents=True, exist_ok=True)

    def _load_registry(self):
        """Load SN registry from JSON"""
        if SN_REGISTRY_FILE.exists():
            try:
                with open(SN_REGISTRY_FILE, 'r', encoding='utf-8') as f:
                    self._registry = json.load(f)
                self._default_template = self._registry.get('default_template', 'standard_unlock')
                self._patterns = self._registry.get('sn_patterns', [])

                # Load device-specific configs
                devices = self._registry.get('devices', {})
                for sn, cfg in devices.items():
                    self._device_configs[sn] = DeviceConfig(
                        serial_number=sn,
                        template_name=cfg.get('template', self._default_template),
                        custom_params=cfg.get('custom_params', {}),
                        enabled=cfg.get('enabled', True),
                        name=cfg.get('name', ''),
                        notes=cfg.get('notes', '')
                    )
                logging.info(f"Loaded SN registry with {len(self._device_configs)} devices")
            except Exception as e:
                logging.error(f"Failed to load SN registry: {e}")

    def _load_templates(self):
        """Load all templates from templates directory"""
        if not TEMPLATES_DIR.exists():
            return

        for tpl_file in TEMPLATES_DIR.glob("*.json"):
            try:
                with open(tpl_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                template_name = tpl_file.stem
                sequences = []

                for seq_data in data.get('sequences', []):
                    params = [
                        SetParam(
                            name=p['Name'],
                            value=p['Value'],
                            xtype=p.get('Type', 'xsd:string')
                        )
                        for p in seq_data.get('params', [])
                    ]
                    sequences.append(UnlockSequence(
                        name=seq_data['name'],
                        description=seq_data.get('description', ''),
                        params=params
                    ))

                superadmin = data.get('superadmin', {})
                superadmin_params = [
                    SetParam(
                        name=p['Name'],
                        value=p['Value'],
                        xtype=p.get('Type', 'xsd:string')
                    )
                    for p in superadmin.get('params', [])
                ] if superadmin.get('enabled') else []

                wifi = data.get('wifi_config', {})
                wifi_params = [
                    SetParam(
                        name=p['Name'],
                        value=p['Value'],
                        xtype=p.get('Type', 'xsd:string')
                    )
                    for p in wifi.get('params', [])
                ] if wifi.get('enabled') else []

                self._templates[template_name] = DeviceTemplate(
                    name=data.get('name', template_name),
                    description=data.get('description', ''),
                    version=data.get('version', '1.0'),
                    sequences=sequences,
                    superadmin_enabled=superadmin.get('enabled', False),
                    superadmin_params=superadmin_params,
                    wifi_config_enabled=wifi.get('enabled', False),
                    wifi_params=wifi_params
                )
                logging.info(f"Loaded template: {template_name}")
            except Exception as e:
                logging.error(f"Failed to load template {tpl_file}: {e}")

    def get_template_for_sn(self, serial_number: str) -> Optional[DeviceTemplate]:
        """Get template for a serial number based on patterns or specific config"""
        # First check for specific device config
        if serial_number in self._device_configs:
            cfg = self._device_configs[serial_number]
            if cfg.enabled:
                template_name = cfg.template_name
                return self._templates.get(template_name)

        # Then check patterns
        for pattern_cfg in self._patterns:
            pattern = pattern_cfg.get('pattern', '')
            if re.match(pattern, serial_number):
                template_name = pattern_cfg.get('template', self._default_template)
                return self._templates.get(template_name)

        # Fallback to default
        return self._templates.get(self._default_template)

    def get_config_for_sn(self, serial_number: str) -> DeviceConfig:
        """Get or create device config for serial number"""
        if serial_number not in self._device_configs:
            template = self.get_template_for_sn(serial_number)
            template_name = self._default_template

            # Find matching pattern
            for pattern_cfg in self._patterns:
                pattern = pattern_cfg.get('pattern', '')
                if re.match(pattern, serial_number):
                    template_name = pattern_cfg.get('template', self._default_template)
                    break

            self._device_configs[serial_number] = DeviceConfig(
                serial_number=serial_number,
                template_name=template_name,
                template=template,
                enabled=True
            )

        cfg = self._device_configs[serial_number]
        if cfg.template is None:
            cfg.template = self._templates.get(cfg.template_name)

        return cfg

    def get_all_params_for_sn(self, serial_number: str) -> List[SetParam]:
        """Get all parameters to set for a serial number"""
        config = self.get_config_for_sn(serial_number)
        if not config.enabled or not config.template:
            return []

        all_params: List[SetParam] = []
        template = config.template

        # Add all sequence params
        for seq in template.sequences:
            all_params.extend(seq.params)

        # Add superadmin params if enabled
        if template.superadmin_enabled:
            all_params.extend(template.superadmin_params)

        # Add wifi params if enabled
        if template.wifi_config_enabled:
            all_params.extend(template.wifi_params)

        # Apply custom param overrides
        for param in all_params:
            if param.name in config.custom_params:
                param.value = config.custom_params[param.name]

        return all_params

    def get_unlock_sequences_for_sn(self, serial_number: str) -> List[UnlockSequence]:
        """Get unlock sequences for a serial number (for staged unlock)"""
        config = self.get_config_for_sn(serial_number)
        if not config.enabled or not config.template:
            return []

        sequences = list(config.template.sequences)

        # Add superadmin as a sequence if enabled
        if config.template.superadmin_enabled and config.template.superadmin_params:
            sequences.append(UnlockSequence(
                name="superadmin",
                description="Configure SuperAdmin user",
                params=config.template.superadmin_params
            ))

        return sequences

    def register_device(self, serial_number: str, template: str = None,
                       name: str = "", notes: str = "", enabled: bool = True):
        """Register a new device with specific configuration"""
        self._device_configs[serial_number] = DeviceConfig(
            serial_number=serial_number,
            template_name=template or self._default_template,
            enabled=enabled,
            name=name,
            notes=notes
        )
        self._save_registry()

    def _save_registry(self):
        """Save registry back to file"""
        devices = {}
        for sn, cfg in self._device_configs.items():
            devices[sn] = {
                'template': cfg.template_name,
                'enabled': cfg.enabled,
                'name': cfg.name,
                'notes': cfg.notes,
                'custom_params': cfg.custom_params
            }

        self._registry['devices'] = devices

        with open(SN_REGISTRY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._registry, f, indent=2, ensure_ascii=False)

    def list_templates(self) -> List[str]:
        """List all available templates"""
        return list(self._templates.keys())

    def list_devices(self) -> Dict[str, DeviceConfig]:
        """List all registered devices"""
        return self._device_configs.copy()

    def reload(self):
        """Reload all configurations"""
        self._registry = {}
        self._templates = {}
        self._device_configs = {}
        self._patterns = []
        self._load_registry()
        self._load_templates()


# =========================
# Device Registry Class
# =========================
class DeviceRegistry:
    """Registry for tracking device information and status"""

    def __init__(self):
        self._devices: Dict[str, DeviceInfo] = {}
        self._load()

    def _load(self):
        """Load device registry from file"""
        if DEVICE_REGISTRY_FILE.exists():
            try:
                with open(DEVICE_REGISTRY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for sn, info in data.get('devices', {}).items():
                    self._devices[sn] = DeviceInfo(
                        serial_number=sn,
                        oui=info.get('oui', ''),
                        product_class=info.get('product_class', ''),
                        vendor=info.get('vendor', ''),
                        software_version=info.get('software_version', ''),
                        hardware_version=info.get('hardware_version', ''),
                        wan_ip=info.get('wan_ip', ''),
                        mac_address=info.get('mac_address', ''),
                        connection_url=info.get('connection_url', ''),
                        first_seen=info.get('first_seen', ''),
                        last_seen=info.get('last_seen', ''),
                        status=info.get('status', 'offline'),
                        unlock_progress=info.get('unlock_progress', 0),
                        config_applied=info.get('config_applied', False),
                        events=info.get('events', [])
                    )
                logging.info(f"Loaded device registry with {len(self._devices)} devices")
            except Exception as e:
                logging.error(f"Failed to load device registry: {e}")

    def _save(self):
        """Save device registry to file"""
        devices = {}
        for sn, info in self._devices.items():
            devices[sn] = {
                'oui': info.oui,
                'product_class': info.product_class,
                'vendor': info.vendor,
                'software_version': info.software_version,
                'hardware_version': info.hardware_version,
                'wan_ip': info.wan_ip,
                'mac_address': info.mac_address,
                'connection_url': info.connection_url,
                'first_seen': info.first_seen,
                'last_seen': info.last_seen,
                'status': info.status,
                'unlock_progress': info.unlock_progress,
                'config_applied': info.config_applied,
                'events': info.events[-100:]  # Keep last 100 events
            }

        data = {
            'description': 'Device Registry - Stores device information and status',
            'version': '1.0',
            'devices': devices
        }

        with open(DEVICE_REGISTRY_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def update_device(self, serial_number: str, oui: str = "", product_class: str = "",
                      vendor: str = "", software_version: str = "", hardware_version: str = "",
                      wan_ip: str = "", mac_address: str = "", connection_url: str = "",
                      status: str = None, unlock_progress: int = None, config_applied: bool = None):
        """Update or create device info"""
        now = datetime.now().isoformat()

        if serial_number in self._devices:
            info = self._devices[serial_number]
            info.last_seen = now
            if oui: info.oui = oui
            if product_class: info.product_class = product_class
            if vendor: info.vendor = vendor
            if software_version: info.software_version = software_version
            if hardware_version: info.hardware_version = hardware_version
            if wan_ip: info.wan_ip = wan_ip
            if mac_address: info.mac_address = mac_address
            if connection_url: info.connection_url = connection_url
            if status: info.status = status
            if unlock_progress is not None: info.unlock_progress = unlock_progress
            if config_applied is not None: info.config_applied = config_applied
        else:
            self._devices[serial_number] = DeviceInfo(
                serial_number=serial_number,
                oui=oui,
                product_class=product_class,
                vendor=vendor,
                software_version=software_version,
                hardware_version=hardware_version,
                wan_ip=wan_ip,
                mac_address=mac_address,
                connection_url=connection_url,
                first_seen=now,
                last_seen=now,
                status=status or 'online',
                unlock_progress=unlock_progress or 0,
                config_applied=config_applied or False
            )

        self._save()

    def add_event(self, serial_number: str, event: str):
        """Add an event to device history"""
        if serial_number in self._devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._devices[serial_number].events.append(f"[{timestamp}] {event}")
            self._save()

    def get_device(self, serial_number: str) -> Optional[DeviceInfo]:
        """Get device info"""
        return self._devices.get(serial_number)

    def get_all_devices(self) -> Dict[str, DeviceInfo]:
        """Get all devices"""
        return self._devices.copy()

    def get_online_devices(self) -> Dict[str, DeviceInfo]:
        """Get only online devices"""
        return {sn: info for sn, info in self._devices.items()
                if info.status in ('online', 'unlocking')}

    def set_offline(self, serial_number: str):
        """Mark device as offline"""
        if serial_number in self._devices:
            self._devices[serial_number].status = 'offline'
            self._save()

    def delete_device(self, serial_number: str):
        """Delete device from registry"""
        if serial_number in self._devices:
            del self._devices[serial_number]
            self._save()


# =========================
# Singleton instances
# =========================
_config_loader: Optional[SNConfigLoader] = None
_device_registry: Optional[DeviceRegistry] = None


def get_config_loader() -> SNConfigLoader:
    """Get or create config loader singleton"""
    global _config_loader
    if _config_loader is None:
        _config_loader = SNConfigLoader()
    return _config_loader


def get_device_registry() -> DeviceRegistry:
    """Get or create device registry singleton"""
    global _device_registry
    if _device_registry is None:
        _device_registry = DeviceRegistry()
    return _device_registry


# =========================
# Module initialization
# =========================
if __name__ == "__main__":
    # Test loading
    logging.basicConfig(level=logging.DEBUG)

    loader = get_config_loader()
    print("\n=== Templates ===")
    for t in loader.list_templates():
        print(f"  - {t}")

    print("\n=== Test SN Config ===")
    test_sn = "48575443ABCD1234"
    config = loader.get_config_for_sn(test_sn)
    print(f"SN: {test_sn}")
    print(f"Template: {config.template_name}")

    params = loader.get_all_params_for_sn(test_sn)
    print(f"Parameters ({len(params)}):")
    for p in params:
        print(f"  - {p.name} = {p.value}")

    sequences = loader.get_unlock_sequences_for_sn(test_sn)
    print(f"\nUnlock Sequences ({len(sequences)}):")
    for seq in sequences:
        print(f"  - {seq.name}: {len(seq.params)} params")
