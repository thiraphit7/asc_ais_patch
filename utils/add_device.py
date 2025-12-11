#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility to add devices to the SN registry
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from sn_config_loader import get_config_loader


def main():
    parser = argparse.ArgumentParser(description="Add device to SN registry")
    parser.add_argument("serial_number", help="Device serial number")
    parser.add_argument("--template", "-t", default=None, help="Template name")
    parser.add_argument("--name", "-n", default="", help="Device name")
    parser.add_argument("--notes", default="", help="Notes")
    parser.add_argument("--disabled", action="store_true", help="Add as disabled")

    args = parser.parse_args()

    loader = get_config_loader()

    # List available templates if none specified
    if args.template is None:
        print("Available templates:")
        for t in loader.list_templates():
            print(f"  - {t}")
        args.template = input("Enter template name: ").strip() or "standard_unlock"

    loader.register_device(
        serial_number=args.serial_number,
        template=args.template,
        name=args.name,
        notes=args.notes,
        enabled=not args.disabled
    )

    print(f"Device {args.serial_number} registered with template {args.template}")


if __name__ == "__main__":
    main()
