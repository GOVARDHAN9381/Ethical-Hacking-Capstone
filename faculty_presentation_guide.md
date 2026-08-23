# Faculty Presentation & Live Demo Guide: APIAST

This document serves as your complete guide to presenting the **Intelligent API Security Testing Platform (APIAST)** to your faculty panel. It contains a slide outline, live-demo script talking points, and answers to expected technical Q&A.

---

## 1. Presentation Structure (15–20 Mins)

A standard academic defense is structured into four main phases:

1. **The Problem & Goal (3 mins)**:
   * **The Problem**: Web API interfaces represent the largest attack surface for modern applications. The **OWASP API Security Top 10** identifies key flaws (like Broken Object Level Authorization and Injection) that traditional web scanners miss because APIs don't use standard HTML web pages.
   * **The Goal**: Develop a automated, intelligent security testing platform (APIAST) that dynamically discovers endpoints, executes active security scans, runs AI-augmented risk analysis, and produces remediation reports.

2. **System Architecture (4 mins)**:
   Explain the engineering stack:
   * **Framework**: Flask for web UI, dashboards, and REST API management.
   * **Database**: SQLite managed through SQLAlchemy ORM for scan states, findings, and histories.
   * **Concurrency**: Python's `threading` library to execute non-blocking, multi-stage scans concurrently.
   * **Intelligence**: AI Risk & Compliance Engines evaluating findings to rank remediations.

3. **Live API Demo (7 mins)**:
   * Run the automated demo script to show endpoints discovery, testing, and reports generation in real-time.

4. **Technical Q&A (6 mins)**:
   * Handle committee questions on scanning logic, architecture decisions, and database design.

---

## 2. Live Demo Guide (Step-by-Step)

For the live demo, you will test a **real, intentionally vulnerable target API** running locally on port `5001` (from `demo_target/app.py`) using the automated script we created in `demo_faculty_presentation.py`.

### Demo Setup
Before the presentation starts, run both applications in separate terminals:
1. **Core Scanner (Port 5000)**: `python app.py`
2. **Vulnerable Target API (Port 5001)**: `python demo_target/app.py`

---

### Step-by-Step Demo Walkthrough

#### Step 1: Explain the Target API (Port 5001)
* **Action**: Point the faculty to the Target API schema on `http://localhost:5001/openapi.json`.
* **Talking Points**:
  > *"To demonstrate our scanner, we created a realistic, vulnerable microservice target running on port 5001. It exposes endpoints like login, search, and user profile endpoints. It simulates common design flaws including SQL injection vulnerability in the login parameters, a Broken Object Level Authorization (BOLA) flaw on the `/api/v1/users/{id}` endpoint, and lacks HTTP security headers."*

#### Step 2: Trigger the Scan & Show Concurrency
* **Action**: Run the automated demo runner from the terminal:
  ```bash
  python demo_faculty_presentation.py
  ```
* **Talking Points**:
  > *"I am starting the scan by sending a POST request to `/api/scan/start` on our main scanner application. The scanner spawns a background thread immediately, returning a `202 Accepted` status with a unique session ID. This prevents the request from blocking the client, allowing us to poll or stream status updates in real-time."*

#### Step 3: Explain the Scanning Logic
* **Action**: Observe the script polling status updates (`PENDING` -> `RUNNING` -> `COMPLETED`).
* **Talking Points**:
  > *"As the scan executes, the background thread performs four modules:*
  > 1. **API Discovery**: *It parses the target's `/openapi.json` specification to inventory endpoints.*
  > 2. **Auth Testing**: *It checks for broken authentication, weak JWT secrets, or authorization bypasses.*
  > 3. **Vulnerability Assessment**: *It active-fuzzes endpoints with SQL injection payloads and Cross-Site Scripting (XSS) inputs.*
  > 4. **Enrichment**: *It maps found issues to their respective OWASP API Top 10 categories."*

#### Step 4: Present Findings & AI Risk Scores
* **Action**: Highlight the console output containing the discovered vulnerabilities and risk scores.
* **Talking Points**:
  > *"Our scan found SQL Injection vulnerabilities on the `/api/v1/login` route and missing security headers. Our AI Risk engine dynamically rated the target's overall security posture. It generated a Security Score, an overall Risk Score, and calculated OWASP compliance coverage, highlighting critical remediations."*

#### Step 5: Generate and Show the PDF Report
* **Action**: Open the generated `faculty_demo_report.pdf` file in a PDF reader.
* **Talking Points**:
  > *"Finally, we request our reporting endpoint `/api/monitor/report/{session_id}/pdf`. The system compiles all findings, severities, descriptions, and remediations into an executive PDF report. This demonstrates a complete security audit pipeline."*

---

## 3. Anticipated Faculty Questions & Answers

Be prepared to answer these technical deep-dives:

### Q1: How does your system discover endpoints if an OpenAPI/Swagger spec is missing?
* **Answer**:
  > *"If the target lacks a `/openapi.json` spec, our API Discovery module falls back to standard crawling and brute-forcing. We maintain a dictionary of common API paths (e.g., `/api/v1/users`, `/health`) and query them with varying HTTP verbs (GET, POST, PUT, DELETE) to probe for responses and identify valid routes."*

### Q2: How does the scanner validate that a vulnerability is a true positive instead of a false positive?
* **Answer**:
  > *"We perform active validation. For example, in SQL Injection, we do not just rely on HTTP status codes. We inspect the response body for database error signatures (like SQLite or MySQL syntax warnings). For authorization checks, we verify if accessing resource IDs of other users returns a `200 OK` (vulnerable BOLA) or a `403 Forbidden` / `401 Unauthorized` (secured)."*

### Q3: Why did you choose SQLite and an in-memory DB for testing?
* **Answer**:
  > *"SQLite is lightweight and serverless, which fits local deployment. For testing, an in-memory database (`sqlite:///:memory:`) is ideal because it executes entirely in RAM, runs extremely fast, and automatically drops all data when the test process finishes, ensuring perfect isolation between tests."*

### Q4: How does the SSE (Server-Sent Events) streaming work in app.py?
* **Answer**:
  > *"Flask uses generator yields to stream messages to the client. When a scan starts, we register a listener queue for that session ID. The background worker pushes log events into the queues, and the SSE connection reads from the queue, yielding them to the browser as a `text/event-stream` stream."*
