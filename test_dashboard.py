import unittest
from datetime import datetime, timezone

# Override database configuration before importing Flask app and initializing DB
import config
config.SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

from app import create_app
from db.models import db, ScanSession, VulnFinding, RiskAnalysis, Alert, MonitorSchedule, ApiInventory

class TestDashboardAPI(unittest.TestCase):
    def setUp(self):
        # Create a test instance of the application
        self.app = create_app()
        self.app.config['TESTING'] = True
        
        # Set up Flask test client
        self.client = self.app.test_client()
        
        # Establish application context and create all tables
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        # Clean up database and remove application context
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_dashboard_stats_empty(self):
        """Test dashboard stats when the database is completely empty."""
        response = self.client.get('/api/dashboard/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        
        self.assertEqual(data['total_scans'], 0)
        self.assertEqual(data['completed_scans'], 0)
        self.assertEqual(data['total_vulns'], 0)
        self.assertEqual(data['avg_security_score'], None)
        self.assertEqual(data['avg_compliance_score'], None)

    def test_dashboard_stats_with_data(self):
        """Test dashboard stats when database contains scans, findings, alerts, and schedules."""
        # 1. Create a completed scan session
        session = ScanSession(
            target_url="http://example.com",
            scan_type="full",
            status="COMPLETED",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(session)
        db.session.commit()  # commit to generate session.id
        
        # 2. Add vulnerability findings
        finding1 = VulnFinding(
            session_id=session.id,
            vuln_type="SQL Injection",
            owasp_category="API8",
            severity="CRITICAL",
            cvss_score=9.8
        )
        finding2 = VulnFinding(
            session_id=session.id,
            vuln_type="Broken Authentication",
            owasp_category="API2",
            severity="HIGH",
            cvss_score=8.5
        )
        db.session.add_all([finding1, finding2])
        
        # 3. Add a corresponding risk analysis
        analysis = RiskAnalysis(
            session_id=session.id,
            overall_score=7.5,
            security_score=45.0,
            compliance_score=80.0,
            risk_level="HIGH",
            total_vulns=2,
            critical_count=1,
            high_count=1,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(analysis)
        
        # 4. Add an unacknowledged alert, an active schedule, and an inventory entry
        alert = Alert(session_id=session.id, message="Critical issue found", severity="CRITICAL", acknowledged=False)
        schedule = MonitorSchedule(target_url="http://example.com", active=True)
        inventory = ApiInventory(session_id=session.id, base_url="http://example.com")
        db.session.add_all([alert, schedule, inventory])
        
        db.session.commit()
        
        # Call the stats API endpoint
        response = self.client.get('/api/dashboard/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        
        # Assertions to ensure math and counts are correct
        self.assertEqual(data['total_scans'], 1)
        self.assertEqual(data['completed_scans'], 1)
        self.assertEqual(data['total_vulns'], 2)
        self.assertEqual(data['critical_vulns'], 1)
        self.assertEqual(data['high_vulns'], 1)
        self.assertEqual(data['unacked_alerts'], 1)
        self.assertEqual(data['active_schedules'], 1)
        self.assertEqual(data['api_count'], 1)
        self.assertEqual(data['avg_security_score'], 45.0)
        self.assertEqual(data['avg_compliance_score'], 80.0)

    def test_dashboard_trend(self):
        """Test dashboard trend API returns the correct list of completed scan records."""
        # Create a completed scan session
        session = ScanSession(
            target_url="http://example.com",
            scan_type="full",
            status="COMPLETED",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(session)
        db.session.commit()
        
        # Add risk analysis
        analysis = RiskAnalysis(
            session_id=session.id,
            overall_score=7.5,
            security_score=45.0,
            compliance_score=80.0,
            risk_level="HIGH",
            total_vulns=2,
            critical_count=1,
            high_count=1,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Call the trend API endpoint
        response = self.client.get('/api/dashboard/trend')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        
        # Assertions
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['session_id'], session.id)
        self.assertEqual(data[0]['target_url'], "http://example.com")
        self.assertEqual(data[0]['security_score'], 45.0)
        self.assertEqual(data[0]['compliance_score'], 80.0)
        self.assertEqual(data[0]['overall_score'], 7.5)
        self.assertEqual(data[0]['risk_level'], "HIGH")

if __name__ == '__main__':
    unittest.main()
