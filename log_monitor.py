#!/usr/bin/env python3
"""
Enhanced App Usage Monitor
Tracks which apps you're using by monitoring system logs and running processes
Saves to JSON for analysis
"""

import json
import time
import os
import subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict

class AppUsageMonitor:
    """Monitor and log app usage"""
    
    def __init__(self, log_dir=None):
        self.log_dir = Path(log_dir) if log_dir else Path.home() / ".app_logs"
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.app_data = []
        self.file_positions = {}
        self.seen_pids = set()

    def get_log_files(self):
        """Get common log file locations based on OS"""
        log_files = []
        common_paths = [
            "/var/log/system.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            os.path.expanduser("~/.log"),
        ]

        for path in common_paths:
            if os.path.exists(path):
                log_files.append(path)
                if path not in self.file_positions:
                    self.file_positions[path] = 0

        return log_files

    def read_log_file(self, file_path, last_position=0):
        """Read new lines from a log file since last position"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                lines = f.readlines()
                new_position = f.tell()
                return lines, new_position
        except (IOError, OSError) as e:
            print(f"Error reading {file_path}: {e}")
            return [], last_position

    def get_running_apps(self):
        """Get list of currently running applications"""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )

            apps = []
            for line in result.stdout.split('\n'):
                if '.app' in line and 'grep' not in line:
                    parts = line.split()
                    if len(parts) >= 11:
                        app_path = parts[10]
                        app_name = app_path.split('/')[-1]
                        pid = parts[1]

                        apps.append({
                            "type": "running_app",
                            "user": parts[0],
                            "pid": pid,
                            "cpu": parts[2],
                            "memory": parts[3],
                            "app_path": app_path,
                            "app_name": app_name,
                            "timestamp": datetime.now().isoformat()
                        })

                        # Track if this is a new app launch
                        if pid not in self.seen_pids:
                            self.seen_pids.add(pid)
                            apps[-1]["status"] = "launched"

            return apps
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"Error getting running apps: {e}")
            return []

    def filter_app_related_logs(self, lines):
        """Filter log lines that mention app-related activities"""
        app_keywords = [
            'launchd', 'launch', 'app', 'process', 'killed', 'exit',
            'running', 'started', 'stopped', 'terminated', 'crashed',
            'chrome', 'safari', 'finder', 'mail', 'slack', 'vscode',
            'terminal', 'code', 'editor', 'browser'
        ]

        filtered = []
        for line in lines:
            if any(keyword in line.lower() for keyword in app_keywords):
                filtered.append(line.strip())

        return filtered

    def monitor_logs(self, duration_seconds=300, interval=5):
        """
        Monitor logs and apps for specified duration
        
        Args:
            duration_seconds: How long to monitor (default 5 minutes = 300 seconds)
            interval: Check interval in seconds (default every 5 seconds)
        """
        log_files = self.get_log_files()

        if not log_files:
            print("Warning: No log files found")

        print(f"\n{'='*70}")
        print("APP USAGE MONITOR - STARTED")
        print(f"{'='*70}")
        print(f"Duration: {duration_seconds} seconds ({duration_seconds/60:.1f} minutes)")
        print(f"Check interval: {interval} seconds")
        print(f"Log files monitored: {len(log_files)}")
        if log_files:
            for lf in log_files:
                print(f"  - {lf}")
        print(f"Logs saving to: {self.log_dir}")
        print(f"{'='*70}\n")

        start_time = time.time()
        app_sessions = defaultdict(list)

        try:
            iteration = 0
            while time.time() - start_time < duration_seconds:
                iteration += 1
                current_time = datetime.now().strftime('%H:%M:%S')

                # Get running apps
                current_apps = self.get_running_apps()
                for app in current_apps:
                    self.app_data.append(app)
                    app_name = app['app_name']
                    app_sessions[app_name].append({
                        'pid': app['pid'],
                        'cpu': app['cpu'],
                        'memory': app['memory'],
                        'timestamp': app['timestamp'],
                        'status': app.get('status', 'running')
                    })

                    if app.get('status') == 'launched':
                        print(f"[{current_time}] ✓ LAUNCHED: {app_name} (PID: {app['pid']})")

                # Read system logs
                for log_file in log_files:
                    lines, new_pos = self.read_log_file(
                        log_file,
                        self.file_positions[log_file]
                    )
                    self.file_positions[log_file] = new_pos

                    filtered_lines = self.filter_app_related_logs(lines)
                    for line in filtered_lines:
                        self.app_data.append({
                            "type": "system_log",
                            "source": log_file,
                            "content": line,
                            "timestamp": datetime.now().isoformat()
                        })

                # Print summary every 10 iterations
                if iteration % 10 == 0:
                    print(f"[{current_time}] Monitoring... {len(self.app_data)} events captured, "
                          f"{len(app_sessions)} unique apps detected")

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n\n⚠ Monitoring stopped by user")

        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print(f"Monitoring completed in {elapsed:.0f} seconds")
        print(f"Total events captured: {len(self.app_data)}")
        print(f"Unique apps found: {len(app_sessions)}")
        print(f"{'='*70}\n")

        return {
            "app_sessions": dict(app_sessions),
            "duration": elapsed,
            "app_data": self.app_data
        }

    def save_to_json(self, data, filename=None):
        """Save monitored data to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = self.log_dir / f"monitor_{timestamp}.json"
        else:
            filename = self.log_dir / filename

        output = {
            "capture_time": datetime.now().isoformat(),
            "log_file": str(filename),
            "total_events": len(data.get('app_data', [])),
            "duration_seconds": data.get('duration', 0),
            "unique_apps": len(data.get('app_sessions', {})),
            "app_sessions": data.get('app_sessions', {}),
            "events": data.get('app_data', [])
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"✓ Saved to: {filename}")
        return str(filename)

    def generate_report(self):
        """Generate a summary report of app usage"""
        app_counts = defaultdict(int)
        app_details = defaultdict(lambda: {
            'count': 0,
            'total_cpu': 0,
            'total_memory': 0,
            'pids': set()
        })

        for event in self.app_data:
            if event.get('type') == 'running_app':
                app_name = event.get('app_name', 'unknown')
                app_counts[app_name] += 1

                details = app_details[app_name]
                details['count'] += 1
                details['total_cpu'] += float(event.get('cpu', 0))
                details['total_memory'] += float(event.get('memory', 0))
                details['pids'].add(event.get('pid'))

        # Convert sets to lists for JSON serialization
        for app_name in app_details:
            app_details[app_name]['pids'] = list(app_details[app_name]['pids'])

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_events": len(self.app_data),
            "unique_apps": len(app_counts),
            "apps_ranked": sorted(
                [(app, count) for app, count in app_counts.items()],
                key=lambda x: x[1],
                reverse=True
            ),
            "app_details": dict(app_details)
        }

        return report

    def print_report(self, report=None):
        """Print a nicely formatted report"""
        if report is None:
            report = self.generate_report()

        print(f"\n{'='*70}")
        print("APP USAGE REPORT")
        print(f"{'='*70}")
        print(f"Generated: {report['generated_at']}")
        print(f"Total events: {report['total_events']}")
        print(f"Unique apps: {report['unique_apps']}\n")

        if report['apps_ranked']:
            print("TOP APPS (by frequency):")
            for i, (app, count) in enumerate(report['apps_ranked'][:10], 1):
                print(f"  {i}. {app}: {count} events")
        else:
            print("No apps detected")

        print(f"{'='*70}\n")

def analyze_existing_logs(log_dir=None):
    """Analyze existing log files"""
    if log_dir is None:
        log_dir = Path.home() / ".app_logs"

    if not log_dir.exists():
        print(f"Log directory not found: {log_dir}")
        return

    print(f"\n{'='*70}")
    print("ANALYZING EXISTING LOGS")
    print(f"{'='*70}\n")

    all_apps = defaultdict(int)
    total_entries = 0
    log_count = 0

    for log_file in sorted(log_dir.glob("monitor_*.json")):
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
                log_count += 1
                total_entries += data.get('total_events', 0)

                print(f"{log_file.name}")
                print(f"  Entries: {data.get('total_events', 0)}")
                print(f"  Duration: {data.get('duration_seconds', 0):.0f}s")
                print(f"  Unique apps: {data.get('unique_apps', 0)}")

                for app, sessions in data.get('app_sessions', {}).items():
                    all_apps[app] += len(sessions)

        except json.JSONDecodeError as e:
            print(f"Error reading {log_file}: {e}")

    print(f"\n{'='*70}")
    print(f"SUMMARY: {log_count} log files, {total_entries} total events")
    print(f"{'='*70}\n")

    if all_apps:
        print("ALL APPS (combined):")
        for i, (app, count) in enumerate(sorted(all_apps.items(), 
                                                key=lambda x: x[1], reverse=True)[:15], 1):
            print(f"  {i}. {app}: {count}")
        print()

if __name__ == "__main__":
    import sys

    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "analyze":
            analyze_existing_logs()
            sys.exit(0)
        elif sys.argv[1] == "duration":
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 300
        else:
            print("Usage:")
            print("  python3 app_usage_monitor.py              # Monitor for 5 minutes")
            print("  python3 app_usage_monitor.py 600          # Monitor for 10 minutes (600 seconds)")
            print("  python3 app_usage_monitor.py analyze      # Analyze existing logs")
            sys.exit(1)
    else:
        duration = 300

    # Run monitoring
    monitor = AppUsageMonitor()
    data = monitor.monitor_logs(duration_seconds=duration, interval=5)
    
    # Save to JSON
    json_file = monitor.save_to_json(data)
    
    # Generate and print report
    report = monitor.generate_report()
    monitor.print_report(report)
    
    # Also save report as separate JSON
    report_file = monitor.log_dir / "latest_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to: {report_file}")