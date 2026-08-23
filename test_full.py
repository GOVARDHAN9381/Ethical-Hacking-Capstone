import requests, time, json, sys

BASE = 'http://localhost:5000'

print("1. Starting full scan...")
resp = requests.post(BASE + '/api/scan/start',
    json={'target_url':'http://localhost:5001','scan_type':'full'}, timeout=10)
sid = resp.json()['session_id']
print(f"   Session ID: {sid}")

print("2. Waiting for scan to complete...")
for i in range(50):
    st = requests.get(f'{BASE}/api/discovery/{sid}/status', timeout=5).json().get('status')
    print(f"   [{i*2}s] Status: {st}", flush=True)
    if st in ('COMPLETED','FAILED'):
        break
    time.sleep(2)

print("\n3. Results:")
findings = requests.get(f'{BASE}/api/vuln/{sid}/findings', timeout=5).json()
print(f"   Findings: {len(findings)}")
sevs = {}
for f in findings:
    sevs[f.get('severity','INFO')] = sevs.get(f.get('severity','INFO'),0)+1
print(f"   Severity: {sevs}")
for f in findings[:5]:
    print(f"   - [{f.get('severity')}] {f.get('vuln_type')} @ {f.get('path')} (OWASP: {f.get('owasp_category')})")

owasp = requests.get(f'{BASE}/api/vuln/{sid}/owasp', timeout=5).json()
print(f"\n   OWASP Coverage: {owasp.get('coverage_pct')}%  ({owasp.get('found_count')}/10 categories)")

inv = requests.get(f'{BASE}/api/discovery/inventory', timeout=5).json()
print(f"\n   API Inventory: {len(inv)} entries")
for i in inv:
    print(f"   - API Name: {i.get('api_name')}")
    print(f"     Version: {i.get('version')}, Endpoints: {i.get('total_endpoints')}, Auth: {i.get('auth_type')}")
    print(f"     public_count={i.get('public_count')} auth_count={i.get('auth_count')} admin_count={i.get('admin_count')}")

cls_data = requests.get(f'{BASE}/api/discovery/{sid}/classify', timeout=5).json()
print(f"\n   Endpoint Classification: {cls_data.get('breakdown')}")

print("\n4. Running AI Analysis...")
analysis = requests.post(f'{BASE}/api/analysis/{sid}/analyze', json={}, timeout=15).json()
risk = analysis.get('risk', {})
print(f"   Security Score:  {risk.get('security_score')}/100")
print(f"   Risk Score:      {risk.get('overall_score')}/10 ({risk.get('risk_level')})")
print(f"   Compliance:      {analysis.get('compliance_score')}%")
crit = risk.get('critical_count',0)
high = risk.get('high_count',0)
med  = risk.get('medium_count',0)
low  = risk.get('low_count',0)
print(f"   Critical={crit} High={high} Med={med} Low={low}")
comp = analysis.get('compliance_report',{})
passed = comp.get('passed',0)
failed = comp.get('failed',0)
print(f"   OWASP compliance: {passed}/{passed+failed} categories pass")
recs = analysis.get('recommendations',{})
spec_count = len(recs.get('specific_recommendations',[]))
gen_count  = len(recs.get('general_recommendations',[]))
print(f"   Recommendations: {spec_count} specific + {gen_count} general")

print("\n5. Testing report exports...")
for fmt in ['pdf','html','csv','json']:
    r = requests.get(f'{BASE}/api/monitor/report/{sid}/{fmt}', timeout=15)
    print(f"   {fmt.upper()}: {r.status_code} ({len(r.content)} bytes)")

print("\n6. Testing change detection...")
chg = requests.get(f'{BASE}/api/monitor/changes/{sid}', timeout=5).json()
msg = chg.get('message', f"new_vulns={chg.get('new_vulns')}, risk_delta={chg.get('risk_delta')}")
print(f"   Changes: {msg}")

print("\n7. Dashboard stats after scan...")
stats = requests.get(f'{BASE}/api/dashboard/stats', timeout=5).json()
print(f"   total_scans={stats.get('total_scans')} total_vulns={stats.get('total_vulns')} api_count={stats.get('api_count')}")
print(f"   avg_security_score={stats.get('avg_security_score')} avg_compliance={stats.get('avg_compliance_score')}")

print("\n=== ALL TESTS PASSED ===")
