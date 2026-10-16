import sys
import os
from datetime import datetime

from updater import check_for_updates
from version import APP_VERSION

# Ensure 'app' module can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Apply SSL fix for corporate proxies (e.g. Zscaler on bank laptops)
try:
    from app.utils.ssl_patch import apply_ssl_patch
    apply_ssl_patch()
except Exception:
    pass

from app.services.scanner import scan_urls_batch
from app.services.pdf_report import generate_pdf_report

def main():
    print("=========================================")
    print("   URL THREAT SCANNER (CLI Mode)         ")
    print(f"                 v{APP_VERSION}                 ")
    print("=========================================")

    # Check for updates before doing anything else
    check_for_updates(current_version=APP_VERSION)

    # 1. Read URLs
    urls_file = "urls.txt"
    if not os.path.exists(urls_file):
        print(f"[-] Error: '{urls_file}' not found.")
        print(f"[*] Creating empty '{urls_file}' for you...")
        with open(urls_file, "w") as f:
            f.write("https://example.com\n")
        print(f"[*] Please add your URLs to '{urls_file}' and run this script again.")
        sys.exit(1)

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print(f"[-] Error: '{urls_file}' is empty.")
        sys.exit(1)

    print("\n--- Report Details ---")
    print("Type 'NA' or press Enter to skip a field.")
    app_name_input = input("Application Name: ").strip()
    can_id_input = input("CAN ID: ").strip()
    server_ip_input = input("Server IP: ").strip()
    request_id_input = input("Request ID (comma-separated SNs): ").strip()
    comment_input = input("Final Assessment Comment: ").strip()
    print("----------------------\n")

    def parse_input(val):
        return None if not val or val.lower() == "na" else val

    app_name = parse_input(app_name_input)
    can_id = parse_input(can_id_input)
    server_ip = parse_input(server_ip_input)
    request_id = parse_input(request_id_input)
    final_comment = parse_input(comment_input) or ""

    print(f"[*] Loaded {len(urls)} URL(s) to scan.")
    print("[*] Starting scans... This may take a while to respect API rate limits.")

    # 2. Run Scan
    try:
        results = scan_urls_batch(urls)
        print(f"[*] Scans completed successfully for {len(results)} URLs.")
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        sys.exit(1)

    # 3. Generate Report
    print("[*] Generating PDF report...")
    try:
        pdf_bytes = generate_pdf_report(
            results,
            final_comment=final_comment,
            app_name=app_name,
            can_id=can_id,
            server_ip=server_ip,
            request_id=request_id
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_report_{timestamp}.pdf"

        with open(filename, "wb") as f:
            f.write(pdf_bytes)

        print(f"[+] Success! Report saved to: {os.path.abspath(filename)}")
    except Exception as e:
        print(f"[-] PDF generation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
