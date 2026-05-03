#!/usr/bin/env python3
"""
Apache mod_jk Format Parsing Example
=====================================

This example demonstrates parsing Apache mod_jk logs with custom format support.

Run with:
    python examples/parse_modjk_example.py
"""

from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers.factory import LogParser
import pandas as pd


def example_basic_parsing():
    """Basic parsing of mod_jk logs."""
    print("=" * 60)
    print("EXAMPLE 1: Basic Apache mod_jk Parsing")
    print("=" * 60)
    
    # Sample mod_jk log lines
    sample_logs = [
        "[Sun Dec 04 04:51:14 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
        "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
        "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
        "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
        "[Sun Dec 04 04:51:37 2005] [notice] jk2_init() Found child 6736 in scoreboard slot 10",
        "[Sun Dec 04 04:51:38 2005] [notice] jk2_init() Found child 6733 in scoreboard slot 7",
        "[Sun Dec 04 04:51:38 2005] [notice] jk2_init() Found child 6734 in scoreboard slot 9",
        "[Sun Dec 04 04:51:52 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
        "[Sun Dec 04 04:51:52 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
        "[Sun Dec 04 04:51:55 2005] [error] mod_jk child workerEnv in error state 6",
        "[Sun Dec 04 04:52:04 2005] [notice] jk2_init() Found child 6738 in scoreboard slot 6",
        "[Sun Dec 04 04:52:04 2005] [notice] jk2_init() Found child 6741 in scoreboard slot 9",
    ]
    
    # Parse the logs
    print("\nParsing mod_jk logs...")
    df = LogParser.parse(iter(sample_logs), "apache_modjk")
    
    print(f"✓ Parsed {len(df)} log entries\n")
    
    # Display results
    print("First 5 entries:")
    print(df.head()[['timestamp', 'level', 'severity', 'message']].to_string())
    
    print("\n\nLog levels distribution:")
    print(df['level'].value_counts())
    
    return df


def example_with_custom_format():
    """Parsing with custom timestamp format."""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Custom Timestamp Format")
    print("=" * 60)
    
    # Logs with different timestamp format
    sample_logs = [
        "[12/04/2005:04:51:14] [notice] workerEnv.init() ok",
        "[12/04/2005:04:51:18] [error] mod_jk child workerEnv in error state 6",
    ]
    
    # Parse with custom format
    config = {
        'timestamp_format': '%m/%d/%Y:%H:%M:%S'
    }
    
    print(f"\nUsing custom timestamp format: {config['timestamp_format']}")
    df = LogParser.parse(iter(sample_logs), "apache_modjk", config)
    
    print(f"✓ Parsed {len(df)} entries with custom format\n")
    print(df[['timestamp', 'message']].to_string())
    
    return df


def example_worker_analysis(df):
    """Analyze worker-specific information."""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Worker Information Analysis")
    print("=" * 60)
    
    # Filter child process logs
    child_logs = df[df['worker_type'] == 'child_process']
    
    if not child_logs.empty:
        print(f"\n✓ Found {len(child_logs)} child process entries")
        print("\nChild process to slot mapping:")
        for _, row in child_logs.iterrows():
            print(f"  PID {row['child_pid']} → Slot {row['slot']}")
    
    # Filter error states
    error_logs = df[df['error_state'].notna()]
    
    if not error_logs.empty:
        print(f"\n✓ Found {len(error_logs)} error state entries")
        print("\nError states:")
        for state in error_logs['error_state'].unique():
            count = len(error_logs[error_logs['error_state'] == state])
            print(f"  State {state}: {count} occurrences")
    
    # Configuration files
    config_logs = df[df['config_file'].notna()]
    
    if not config_logs.empty:
        print(f"\n✓ Found {len(config_logs)} configuration file references")
        print("\nConfiguration files:")
        for config_file in config_logs['config_file'].unique():
            print(f"  {config_file}")


def example_format_info():
    """Display supported formats."""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Available Formats")
    print("=" * 60)
    
    all_formats = LogParser.get_all_format_info()
    
    print(f"\n✓ {len(all_formats)} supported log formats:\n")
    
    for fmt_name, info in list(all_formats.items())[:6]:
        supports_config = "✓" if info.get('supports_config') else "✗"
        print(f"{fmt_name:20s} {supports_config} {info.get('description', '')}")
    
    print(f"\n... and {len(all_formats) - 6} more formats")
    
    # Detailed info for apache_modjk
    print("\n\nDetailed format info for 'apache_modjk':")
    modjk_info = LogParser.get_format_info("apache_modjk")
    print(f"  Description: {modjk_info.get('description')}")
    print(f"  Supports config: {modjk_info.get('supports_config')}")
    print(f"  Config keys: {modjk_info.get('config_keys')}")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("Apache mod_jk Format Support - Examples")
    print("=" * 60)
    
    # Example 1: Basic parsing
    df = example_basic_parsing()
    
    # Example 2: Custom timestamp format
    example_with_custom_format()
    
    # Example 3: Worker analysis
    example_worker_analysis(df)
    
    # Example 4: Format information
    example_format_info()
    
    print("\n" + "=" * 60)
    print("✓ All examples completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
