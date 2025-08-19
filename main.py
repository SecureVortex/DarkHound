import asyncio
from modules.monitor import DarkWebMonitor
from modules.alerting import AlertManager
from modules.dashboard import run_dashboard

async def main():
    monitor = DarkWebMonitor()
    alert_manager = AlertManager()
    print("[*] Starting DarkHound monitoring engine...")

    async for finding in monitor.scan():
        print(f"[!] Leak Detected: {finding}")
        alert_manager.send_alert(finding)
        monitor.save_finding(finding)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DarkHound - Dark Web Monitoring Tool")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    args = parser.parse_args()

    if args.dashboard:
        run_dashboard()
    else:
        asyncio.run(main())