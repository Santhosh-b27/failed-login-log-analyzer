"""
AuthSentinel CLI: Enterprise Authentication Log Forensics & Threat Detection.
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

# Colorama / ANSI styling helper
try:
    import colorama
    colorama.init(autoreset=True)
    RED = colorama.Fore.RED + colorama.Style.BRIGHT
    GREEN = colorama.Fore.GREEN + colorama.Style.BRIGHT
    YELLOW = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    CYAN = colorama.Fore.CYAN + colorama.Style.BRIGHT
    MAGENTA = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    BLUE = colorama.Fore.BLUE + colorama.Style.BRIGHT
    WHITE = colorama.Fore.WHITE + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    DIM = colorama.Style.DIM
except ImportError:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    DIM = "\033[2m"

from auth_sentinel.core.config import SentinelConfig
from auth_sentinel.core.models import IncidentSummary, AuthEvent, SeverityLevel
from auth_sentinel.parsers.auto_detector import LogParserDispatcher
from auth_sentinel.detection.engine import DetectionEngine
from auth_sentinel.reporting.html_report import HtmlReportGenerator
from auth_sentinel.reporting.siem_export import SiemExporter
from auth_sentinel.generator.log_generator import LogGenerator


ASCII_ART = r"""
    ___          __  __    _____            __  _            __
   /   | __  __ / /_/ /_  / ___/___  ____  / /_(_)___  ___  / /
  / /| |/ / / // __/ __ \ \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
 / ___ / /_/ // /_/ / / /___/ /  __/ / / / /_/ / / / /  __/ /  
/_/  |_\__,_/ \__/_/ /_//____/\___/_/ /_/\__/_/_/ /_/\___/_/   
"""

BANNER = f"{CYAN}{ASCII_ART}{RESET}{DIM}Enterprise Authentication Forensics & Threat Detection Engine v1.0.0{RESET}\n"


def print_banner() -> None:
    print(BANNER)


def print_incident_summary_cli(summary: IncidentSummary, events: List[AuthEvent]) -> None:
    print(f"\n{CYAN}{'='*30} [ SOC FORENSIC OVERVIEW ] {'='*30}{RESET}")
    print(f"Total Logs Ingested:    {WHITE}{summary.total_events}{RESET}")
    print(f"Failed Authentications: {RED}{summary.total_failed}{RESET}")
    print(f"Successful Logins:      {GREEN}{summary.total_success}{RESET}")
    print(f"Unique Source IPs:      {WHITE}{summary.unique_ips}{RESET}")
    print(f"Unique Target Accounts: {WHITE}{summary.unique_users}{RESET}")
    print(f"High-Risk / Malicious:  {RED}{summary.high_risk_ips}{RESET}")
    print(f"Correlated Incidents:   {YELLOW if summary.alerts else GREEN}{len(summary.alerts)}{RESET}")

    # Service Breakdown
    print(f"\n{CYAN}[ Service Protocol Breakdown ]{RESET}")
    for srv, count in sorted(summary.service_breakdown.items(), key=lambda x: x[1], reverse=True):
        print(f"  * {srv:<12}: {WHITE}{count}{RESET}")

    # Alerts Section
    if summary.alerts:
        print(f"\n{RED}{'='*30} [ CRITICAL THREAT ALERTS ({len(summary.alerts)}) ] {'='*30}{RESET}")
        for alt in summary.alerts:
            sev_color = RED if alt.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else YELLOW
            print(f"\n{sev_color}[!] {alt.severity.value}: {alt.attack_type.value}{RESET}")
            print(f"    Alert ID:        {WHITE}{alt.alert_id}{RESET}")
            print(f"    Source IP:       {CYAN}{alt.source_ip}{RESET}")
            print(f"    Target Account:  {MAGENTA}{', '.join(alt.targeted_users)}{RESET}")
            print(f"    Attempts Count:  {WHITE}{alt.attempt_count}{RESET} in {alt.time_window_seconds}s")
            print(f"    MITRE ATT&CK:    {BLUE}{alt.mitre_technique_id} ({alt.mitre_technique_name}){RESET}")
            print(f"    Details:         {alt.description}")
            print(f"    {YELLOW}SOC Action:{RESET}      {alt.recommended_action}")

    # Top Attacking / High Risk IPs Table
    print(f"\n{CYAN}{'='*30} [ IOC & SOURCE IP RISK PROFILES ] {'='*30}{RESET}")
    header = f"{'Source IP':<16} {'Risk':<8} {'Fail/Total':<12} {'Location':<24} {'Target Users':<20}"
    print(header)
    print("-" * 84)

    for ip, prof in sorted(summary.ip_profiles.items(), key=lambda x: (x[1].risk_score, x[1].failed_attempts), reverse=True):
        risk_color = RED if prof.risk_score >= 70 else (YELLOW if prof.risk_score >= 40 else GREEN)
        risk_str = f"{risk_color}{prof.risk_score}/100{RESET}"
        ratio_str = f"{prof.failed_attempts}/{prof.total_attempts}"
        loc_str = f"{prof.geo.city}, {prof.geo.country_code}" if prof.geo else "Unknown"
        users_str = ", ".join(prof.targeted_users[:2]) + (f" (+{len(prof.targeted_users)-2})" if len(prof.targeted_users) > 2 else "")
        print(f"{ip:<16} {risk_str:<17} {ratio_str:<12} {loc_str[:22]:<24} {users_str[:18]:<20}")


def run_analyze(args: argparse.Namespace) -> None:
    print_banner()
    file_path = args.logfile
    if not os.path.exists(file_path):
        print(f"{RED}[-] Error: Log file '{file_path}' does not exist.{RESET}")
        sys.exit(1)

    print(f"{CYAN}[*] Ingesting and parsing log file:{RESET} {file_path}")
    dispatcher = LogParserDispatcher()
    events = dispatcher.parse_file(file_path)

    if not events:
        print(f"{YELLOW}[!] No valid authentication events could be parsed from {file_path}.{RESET}")
        return

    config = SentinelConfig()
    if hasattr(args, "threshold_bf") and args.threshold_bf:
        config.brute_force_threshold = args.threshold_bf
    if hasattr(args, "threshold_spray") and args.threshold_spray:
        config.password_spray_threshold = args.threshold_spray

    print(f"{CYAN}[*] Running multi-vector correlation and threat intelligence engine...{RESET}")
    engine = DetectionEngine(config)
    summary = engine.process_events(events)

    print_incident_summary_cli(summary, events)

    # Export handlers
    if getattr(args, "html", None):
        HtmlReportGenerator.generate(summary, events, args.html)
        print(f"\n{GREEN}[+] Executive HTML Report generated:{RESET} {os.path.abspath(args.html)}")

    if getattr(args, "json", None):
        SiemExporter.export_json(summary, args.json)
        print(f"{GREEN}[+] SIEM JSON export saved:{RESET} {os.path.abspath(args.json)}")

    if getattr(args, "csv", None):
        SiemExporter.export_alerts_csv(summary, args.csv)
        print(f"{GREEN}[+] Forensic CSV export saved:{RESET} {os.path.abspath(args.csv)}")


def run_generate(args: argparse.Namespace) -> None:
    print_banner()
    scenario = args.scenario
    output_path = args.output
    print(f"{CYAN}[*] Generating attack scenario '{scenario}'...{RESET}")
    logs = LogGenerator.generate_scenario(scenario)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(logs) + "\n")
    print(f"{GREEN}[+] Successfully generated {len(logs)} log entries to:{RESET} {os.path.abspath(output_path)}")


def run_watch(args: argparse.Namespace) -> None:
    print_banner()
    file_path = args.logfile
    print(f"{CYAN}[*] Live Sentinel Watch active on: {WHITE}{file_path}{RESET}")
    print(f"{DIM}Monitoring in real-time. Press Ctrl+C to stop...{RESET}\n")

    dispatcher = LogParserDispatcher()
    config = SentinelConfig()
    engine = DetectionEngine(config)
    accumulated_events: List[AuthEvent] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            # Go to end of file
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                event = dispatcher.parse_line(line)
                if event:
                    accumulated_events.append(event)
                    if event.status == "FAILED":
                        print(f"{RED}[FAILED AUTH]{RESET} {event.timestamp.strftime('%H:%M:%S')} | {event.service} | IP: {event.ip} | User: {event.username}")
                    elif event.status == "SUCCESS":
                        print(f"{GREEN}[SUCCESS AUTH]{RESET} {event.timestamp.strftime('%H:%M:%S')} | {event.service} | IP: {event.ip} | User: {event.username}")

                    # Run incremental detection every 5 events
                    if len(accumulated_events) % 3 == 0:
                        summary = engine.process_events(accumulated_events[-20:])
                        for alt in summary.alerts:
                            print(f"{MAGENTA}>>> TRIGGERED ALERT:{RESET} {alt.severity.value} - {alt.attack_type.value} from {alt.source_ip}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Watch session terminated by user.{RESET}")


def run_dashboard(args: argparse.Namespace) -> None:
    import subprocess
    print_banner()
    print(f"{CYAN}[*] Launching AuthSentinel Interactive SOC Web Dashboard...{RESET}")
    dashboard_file = os.path.join(os.path.dirname(__file__), "dashboard.py")
    subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_file])


def main() -> None:
    # If the user ran "python cli.py sample.log" or "python analyzer.py sample.log" directly
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-") and sys.argv[1] not in ("analyze", "generate", "watch", "dashboard"):
        sys.argv.insert(1, "analyze")

    parser = argparse.ArgumentParser(
        description="AuthSentinel: Enterprise Authentication Log Forensics & Threat Detection Platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze authentication log file(s)")
    p_analyze.add_argument("logfile", help="Path to authentication log file")
    p_analyze.add_argument("--html", help="Path to output executive HTML report")
    p_analyze.add_argument("--json", help="Path to output SIEM JSON file")
    p_analyze.add_argument("--csv", help="Path to output forensic CSV file")
    p_analyze.add_argument("--threshold-bf", type=int, help="Custom brute force failure threshold")
    p_analyze.add_argument("--threshold-spray", type=int, help="Custom password spray user threshold")

    # Subcommand: generate
    p_generate = subparsers.add_parser("generate", help="Generate synthetic attack log datasets")
    p_generate.add_argument(
        "--scenario",
        choices=["bruteforce", "spray", "travel", "compromise", "mixed"],
        default="mixed",
        help="Attack scenario to simulate",
    )
    p_generate.add_argument("--output", "-o", default="synthetic_attack.log", help="Output file path")

    # Subcommand: watch
    p_watch = subparsers.add_parser("watch", help="Live tail and monitor a log file in real-time")
    p_watch.add_argument("logfile", help="Log file to monitor")

    # Subcommand: dashboard
    p_dash = subparsers.add_parser("dashboard", help="Launch interactive Streamlit SOC Dashboard")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "analyze":
        run_analyze(args)
    elif args.command == "generate":
        run_generate(args)
    elif args.command == "watch":
        run_watch(args)
    elif args.command == "dashboard":
        run_dashboard(args)


if __name__ == "__main__":
    main()
