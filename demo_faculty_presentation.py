import requests
import time
import sys
import os
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color console logging
init(autoreset=True)

BASE_APP_URL = 'http://localhost:5000'
TARGET_URL = 'http://localhost:5001'

def check_target_reachable():
    """Verify that both the core scanner and the vulnerable demo target are running."""
    try:
        requests.get(BASE_APP_URL, timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] ERROR: Core Scanner Application is not running on {BASE_APP_URL}.")
        print(f"{Fore.YELLOW}    Please start it first (e.g. running 'python app.py').")
        sys.exit(1)

    try:
        requests.get(TARGET_URL + "/health", timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] ERROR: Vulnerable Target Application is not running on {TARGET_URL}.")
        print(f"{Fore.YELLOW}    Please start the target first: 'python demo_target/app.py'")
        sys.exit(1)

def run_faculty_demo():
    check_target_reachable()

    print(f"\n{Fore.CYAN}{Style.BRIGHT}======================================================================")
    print(f"{Fore.CYAN}{Style.BRIGHT}           APIAST: LIVE DEMO RUNNER FOR FACULTY PRESENTATION")
    print(f"{Fore.CYAN}{Style.BRIGHT}======================================================================\n")

    # Step 1: Trigger Scan
    print(f"{Fore.GREEN}[Step 1] Triggering full security scan on target API...")
    print(f"Target URL: {Fore.WHITE}{TARGET_URL}")
    print(f"Endpoint:   {Fore.WHITE}{BASE_APP_URL}/api/scan/start")
    
    try:
        resp = requests.post(
            f"{BASE_APP_URL}/api/scan/start",
            json={'target_url': TARGET_URL, 'scan_type': 'full'},
            timeout=10
        )
        resp_data = resp.json()
        session_id = resp_data.get('session_id')
        print(f"{Fore.GREEN}✔ Scan started successfully!")
        print(f"  Session ID generated: {Fore.YELLOW}{session_id}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to start scan: {e}")
        sys.exit(1)

    # Step 2: Poll Scan Status & Stream Progress
    print(f"{Fore.GREEN}[Step 2] Polling scan status and simulating live streaming...")
    status_url = f"{BASE_APP_URL}/api/discovery/{session_id}/status"
    
    completed = False
    for i in range(30):
        try:
            status_resp = requests.get(status_url, timeout=5)
            status_data = status_resp.json()
            status = status_data.get('status')
            
            print(f"  [{i*2}s] Scan Status: {Fore.YELLOW}{status}")
            
            if status in ('COMPLETED', 'FAILED'):
                completed = (status == 'COMPLETED')
                break
        except Exception as e:
            print(f"  Error polling status: {e}")
            
        time.sleep(2)

    if not completed:
        print(f"\n{Fore.RED}[!] Scan did not complete successfully or timed out.")
        sys.exit(1)
        
    print(f"{Fore.GREEN}✔ Scan completed successfully!\n")

    # Step 3: Fetch Findings & OWASP Top 10 Coverage
    print(f"{Fore.GREEN}[Step 3] Retrieving discovered vulnerabilities...")
    findings_url = f"{BASE_APP_URL}/api/vuln/{session_id}/findings"
    owasp_url = f"{BASE_APP_URL}/api/vuln/{session_id}/owasp"
    
    try:
        findings = requests.get(findings_url, timeout=5).json()
        owasp_coverage = requests.get(owasp_url, timeout=5).json()
        
        print(f"  Total findings found: {Fore.YELLOW}{len(findings)}")
        print(f"  OWASP Top 10 Coverage: {Fore.YELLOW}{owasp_coverage.get('coverage_pct')}% ({owasp_coverage.get('found_count')}/10 categories)\n")
        
        # Display top 5 findings
        print(f"  {Fore.CYAN}Top Findings Discovered:")
        for idx, f in enumerate(findings[:5], 1):
            severity = f.get('severity', 'INFO')
            sev_color = Fore.BLUE
            if severity == 'CRITICAL':
                sev_color = Fore.RED + Style.BRIGHT
            elif severity == 'HIGH':
                sev_color = Fore.RED
            elif severity == 'MEDIUM':
                sev_color = Fore.YELLOW
            
            print(f"    {idx}. [{sev_color}{severity}{Fore.RESET}] {Fore.WHITE}{f.get('vuln_type')}{Fore.RESET} @ {f.get('path')} (OWASP: {f.get('owasp_category')})")
        print()
    except Exception as e:
        print(f"{Fore.RED}Failed to retrieve findings: {e}\n")

    # Step 4: AI Risk Engine and Advisor Analysis
    print(f"{Fore.GREEN}[Step 4] Requesting AI Risk Analysis & Compliance scoring...")
    analysis_url = f"{BASE_APP_URL}/api/analysis/{session_id}/analyze"
    
    try:
        analysis = requests.post(analysis_url, json={}, timeout=20).json()
        risk = analysis.get('risk', {})
        
        print(f"  Security Score:  {Fore.GREEN if risk.get('security_score',0) > 70 else Fore.RED}{risk.get('security_score')}/100")
        print(f"  Risk Score:      {Fore.YELLOW}{risk.get('overall_score')}/10 ({risk.get('risk_level')})")
        print(f"  Compliance Score:{Fore.GREEN if analysis.get('compliance_score',0) > 70 else Fore.RED}{analysis.get('compliance_score')}%")
        
        recs = analysis.get('recommendations', {})
        print(f"  Recommendations Generated: {Fore.YELLOW}{len(recs.get('specific_recommendations', []))} specific remediation steps\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to run risk analysis: {e}\n")

    # Step 5: Exporting Security Report PDF
    print(f"{Fore.GREEN}[Step 5] Exporting executive security report (PDF format)...")
    report_url = f"{BASE_APP_URL}/api/monitor/report/{session_id}/pdf"
    
    try:
        r = requests.get(report_url, timeout=15)
        if r.status_code == 200:
            filename = "faculty_demo_report.pdf"
            with open(filename, "wb") as f:
                f.write(r.content)
            print(f"{Fore.GREEN}✔ Executive report downloaded successfully to: {Fore.YELLOW}{os.path.abspath(filename)}\n")
        else:
            print(f"{Fore.RED}Failed to generate PDF. HTTP Status: {r.status_code}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to download PDF report: {e}\n")

    print(f"{Fore.CYAN}{Style.BRIGHT}======================================================================")
    print(f"{Fore.CYAN}{Style.BRIGHT}                 LIVE DEMO COMPLETED SUCCESSFULLY")
    print(f"{Fore.CYAN}{Style.BRIGHT}======================================================================")

if __name__ == "__main__":
    run_faculty_demo()
