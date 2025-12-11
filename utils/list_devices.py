#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility to list devices from registries
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from sn_config_loader import get_config_loader, get_device_registry


def main():
    parser = argparse.ArgumentParser(description="List devices")
    parser.add_argument("--config", "-c", action="store_true", help="Show config registry")
    parser.add_argument("--runtime", "-r", action="store_true", help="Show runtime registry")
    parser.add_argument("--all", "-a", action="store_true", help="Show all")

    args = parser.parse_args()

    if args.all or args.config or (not args.config and not args.runtime):
        print("\n=== Config Registry ===")
        loader = get_config_loader()
        devices = loader.list_devices()
        if not devices:
            print("  (no devices)")
        for sn, cfg in devices.items():
            print(f"  {sn}: template={cfg.template_name}, enabled={cfg.enabled}")
            if cfg.name:
                print(f"    name: {cfg.name}")
            if cfg.notes:
                print(f"    notes: {cfg.notes}")

    if args.all or args.runtime:
        print("\n=== Device Registry (Runtime) ===")
        registry = get_device_registry()
        devices = registry.get_all_devices()
        if not devices:
            print("  (no devices)")
        for sn, info in devices.items():
            print(f"  {sn}:")
            print(f"    vendor: {info.vendor}")
            print(f"    product: {info.product_class}")
            print(f"    status: {info.status}")
            print(f"    wan_ip: {info.wan_ip}")
            print(f"    unlock_progress: {info.unlock_progress}%")
            print(f"    last_seen: {info.last_seen}")


if __name__ == "__main__":
    main()
