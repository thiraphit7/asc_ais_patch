#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test configuration loading for a serial number
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from sn_config_loader import get_config_loader


def main():
    parser = argparse.ArgumentParser(description="Test config for serial number")
    parser.add_argument("serial_number", help="Device serial number to test")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    loader = get_config_loader()

    print(f"\n=== Configuration for SN: {args.serial_number} ===\n")

    # Get config
    config = loader.get_config_for_sn(args.serial_number)
    print(f"Template: {config.template_name}")
    print(f"Enabled: {config.enabled}")

    if config.template:
        print(f"Template Name: {config.template.name}")
        print(f"Description: {config.template.description}")
        print(f"SuperAdmin Enabled: {config.template.superadmin_enabled}")

    # Get sequences
    print(f"\n=== Unlock Sequences ===")
    sequences = loader.get_unlock_sequences_for_sn(args.serial_number)
    for i, seq in enumerate(sequences, 1):
        print(f"\n{i}. {seq.name}")
        print(f"   Description: {seq.description}")
        print(f"   Parameters ({len(seq.params)}):")
        for p in seq.params:
            if args.verbose:
                print(f"     - {p.name}")
                print(f"       Value: {p.value}")
                print(f"       Type: {p.xtype}")
            else:
                print(f"     - {p.name} = {p.value}")

    # Get all params
    print(f"\n=== All Parameters ===")
    params = loader.get_all_params_for_sn(args.serial_number)
    print(f"Total: {len(params)} parameters")
    if args.verbose:
        for p in params:
            print(f"  - {p.name} = {p.value} ({p.xtype})")


if __name__ == "__main__":
    main()
