# VulnScanner Pro - API Examples

## Complete Workflow Examples

### 1. Basic Vulnerability Scan

```bash
# Step 1: Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "securityteam",
    "email": "security@company.com",
    "password": "SecurePass123!",
    "fullName": "Security Team",
    "organization": "Acme Corp"
  }'

# Step 2: Login
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "securityteam",
    "password": "SecurePass123!"
  }' | jq -r '.token')

# Step 3: Detect Technology Stack
curl -X POST http://localhost:8080/api/technology/detect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://your-app.com"
  }'

# Response:
{
  "frontend": "REACT",
  "backend": "SPRING_BOOT",
  "database": "POSTGRESQL",
  "cdn": "Cloudflare",
  "waf": "Cloudflare WAF",
  "securityFeatures": {
    "csrfProtection": true,
    "authMethod": "JWT/Bearer Token",
    "hasWAF": true,
    "hasRateLimiting": false
  }
}

# Step 4: Create Target
TARGET_ID=$(curl -X POST http://localhost:8080/api/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Production API",
    "url": "https://api.your-app.com",
    "type": "WEB_APPLICATION",
    "description": "Main production API"
  }' | jq -r '.id')

# Step 5: Start Comprehensive Scan
SCAN_ID=$(curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targetId": '$TARGET_ID',
    "scanType": "FULL_SCAN",
    "includeSubdomains": false,
    "checkSSL": true,
    "detectCMS": true,
    "scanPorts": false,
    "maxDepth": 3
  }' | jq -r '.scanId')

# Step 6: Check Scan Status
curl -X GET "http://localhost:8080/api/scans/$SCAN_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response:
{
  "id": 1,
  "targetId": 1,
  "targetName": "Production API",
  "targetUrl": "https://api.your-app.com",
  "status": "COMPLETED",
  "scanType": "FULL_SCAN",
  "totalVulnerabilities": 12,
  "criticalCount": 2,
  "highCount": 5,
  "mediumCount": 3,
  "lowCount": 2,
  "riskScore": 7.8,
  "startedAt": "2026-01-17T10:30:00",
  "completedAt": "2026-01-17T10:35:23",
  "durationSeconds": 323
}

# Step 7: Get Vulnerabilities
curl -X GET "http://localhost:8080/api/scans/$SCAN_ID/vulnerabilities" \
  -H "Authorization: Bearer $TOKEN"

# Response:
[
  {
    "id": 1,
    "title": "SQL Injection Vulnerability CONFIRMED",
    "description": "The application is vulnerable to SQL injection...",
    "severity": "CRITICAL",
    "cvssScore": 9.8,
    "category": "Injection",
    "cweId": "CWE-89",
    "affectedUrl": "https://api.your-app.com/search?q=test",
    "evidence": "SQL error pattern detected: mysql_fetch_array()...",
    "remediation": "IMMEDIATE ACTION REQUIRED: Use parameterized queries...",
    "confidence": 95
  }
]
```

### 2. Generate Reports for Different Audiences

```bash
# Developer Report (Markdown with code examples)
curl -X GET "http://localhost:8080/api/reports/$SCAN_ID/developer" \
  -H "Authorization: Bearer $TOKEN" \
  -o developer-report.md

# Executive Report (Business risk and ROI)
curl -X GET "http://localhost:8080/api/reports/$SCAN_ID/executive" \
  -H "Authorization: Bearer $TOKEN" \
  -o executive-report.md

# Compliance Report (PCI-DSS, GDPR mapping)
curl -X GET "http://localhost:8080/api/reports/$SCAN_ID/compliance" \
  -H "Authorization: Bearer $TOKEN" \
  -o compliance-report.md
```

### 3. Get All Scans for a Target

```bash
curl -X GET "http://localhost:8080/api/scans/target/$TARGET_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response: Array of all scans for this target
[
  {
    "id": 1,
    "status": "COMPLETED",
    "totalVulnerabilities": 12,
    "criticalCount": 2,
    "riskScore": 7.8,
    "createdAt": "2026-01-17T10:30:00"
  },
  {
    "id": 2,
    "status": "COMPLETED",
    "totalVulnerabilities": 8,
    "criticalCount": 0,
    "riskScore": 5.2,
    "createdAt": "2026-01-16T14:20:00"
  }
]
```

### 4. Quick Scan (Faster, Less Thorough)

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targetId": '$TARGET_ID',
    "scanType": "QUICK_SCAN",
    "checkSSL": true,
    "maxDepth": 1
  }'

# Quick scan focuses on:
# - Critical vulnerabilities only
# - Security headers
# - Common misconfigurations
# Takes 1-2 minutes vs 5-10 minutes for full scan
```

---

## Advanced Examples

### 5. Scan with Custom Configuration

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targetId": '$TARGET_ID',
    "scanType": "CUSTOM_SCAN",
    "includeSubdomains": true,
    "checkSSL": true,
    "detectCMS": true,
    "scanPorts": true,
    "maxDepth": 5
  }'
```

### 6. Monitor Multiple Targets

```bash
# Get all your targets
curl -X GET http://localhost:8080/api/targets \
  -H "Authorization: Bearer $TOKEN"

# Get all scans across all targets
curl -X GET http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN"

# Filter by status
curl -X GET "http://localhost:8080/api/scans?status=RUNNING" \
  -H "Authorization: Bearer $TOKEN"
```

---

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Start scan
        id: scan
        run: |
          TOKEN=$(curl -X POST ${{ secrets.SCANNER_URL }}/api/auth/login \
            -H "Content-Type: application/json" \
            -d '{"username":"${{ secrets.SCANNER_USER }}","password":"${{ secrets.SCANNER_PASS }}"}' \
            | jq -r '.token')
          
          SCAN_ID=$(curl -X POST ${{ secrets.SCANNER_URL }}/api/scans \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{"targetId":${{ secrets.TARGET_ID }},"scanType":"QUICK_SCAN"}' \
            | jq -r '.scanId')
          
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT
          echo "token=$TOKEN" >> $GITHUB_OUTPUT
      
      - name: Wait for scan completion
        run: |
          while true; do
            STATUS=$(curl -X GET "${{ secrets.SCANNER_URL }}/api/scans/${{ steps.scan.outputs.scan_id }}" \
              -H "Authorization: Bearer ${{ steps.scan.outputs.token }}" \
              | jq -r '.status')
            
            if [ "$STATUS" = "COMPLETED" ]; then
              break
            elif [ "$STATUS" = "FAILED" ]; then
              echo "Scan failed"
              exit 1
            fi
            
            sleep 10
          done
      
      - name: Check for critical issues
        run: |
          CRITICAL=$(curl -X GET "${{ secrets.SCANNER_URL }}/api/scans/${{ steps.scan.outputs.scan_id }}" \
            -H "Authorization: Bearer ${{ steps.scan.outputs.token }}" \
            | jq -r '.criticalCount')
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ $CRITICAL critical vulnerabilities found!"
            echo "Download report: ${{ secrets.SCANNER_URL }}/api/reports/${{ steps.scan.outputs.scan_id }}/developer"
            exit 1
          fi
          
          echo "✅ No critical vulnerabilities found"
      
      - name: Generate developer report
        if: failure()
        run: |
          curl -X GET "${{ secrets.SCANNER_URL }}/api/reports/${{ steps.scan.outputs.scan_id }}/developer" \
            -H "Authorization: Bearer ${{ steps.scan.outputs.token }}" \
            -o security-report.md
      
      - name: Comment PR
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-report.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## 🔒 Security Scan Results\n\n' + report
            });
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        SCANNER_URL = 'http://vulnscanner.internal.com:8080'
        SCANNER_CREDS = credentials('vulnscanner-credentials')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Login
                    def loginResponse = sh(
                        script: """
                            curl -X POST ${SCANNER_URL}/api/auth/login \
                                -H 'Content-Type: application/json' \
                                -d '{"username":"${SCANNER_CREDS_USR}","password":"${SCANNER_CREDS_PSW}"}'
                        """,
                        returnStdout: true
                    )
                    def token = readJSON(text: loginResponse).token
                    
                    // Start scan
                    def scanResponse = sh(
                        script: """
                            curl -X POST ${SCANNER_URL}/api/scans \
                                -H 'Content-Type: application/json' \
                                -H 'Authorization: Bearer ${token}' \
                                -d '{"targetId":${TARGET_ID},"scanType":"FULL_SCAN"}'
                        """,
                        returnStdout: true
                    )
                    def scanId = readJSON(text: scanResponse).scanId
                    
                    // Wait for completion
                    timeout(time: 10, unit: 'MINUTES') {
                        waitUntil {
                            def statusResponse = sh(
                                script: """
                                    curl -X GET ${SCANNER_URL}/api/scans/${scanId} \
                                        -H 'Authorization: Bearer ${token}'
                                """,
                                returnStdout: true
                            )
                            def status = readJSON(text: statusResponse).status
                            return status == 'COMPLETED' || status == 'FAILED'
                        }
                    }
                    
                    // Check results
                    def resultsResponse = sh(
                        script: """
                            curl -X GET ${SCANNER_URL}/api/scans/${scanId} \
                                -H 'Authorization: Bearer ${token}'
                        """,
                        returnStdout: true
                    )
                    def results = readJSON(text: resultsResponse)
                    
                    if (results.criticalCount > 0) {
                        error("Security scan failed: ${results.criticalCount} critical vulnerabilities found")
                    }
                }
            }
        }
    }
    
    post {
        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME}",
                body: "Critical vulnerabilities found. Check the build logs for details.",
                to: "security-team@company.com"
            )
        }
    }
}
```

---

## Monitoring & Alerting

### Slack Webhook Integration

```bash
# After scan completes, send Slack notification
SCAN_RESULTS=$(curl -X GET "http://localhost:8080/api/scans/$SCAN_ID" \
  -H "Authorization: Bearer $TOKEN")

CRITICAL=$(echo $SCAN_RESULTS | jq -r '.criticalCount')
HIGH=$(echo $SCAN_RESULTS | jq -r '.highCount')
RISK_SCORE=$(echo $SCAN_RESULTS | jq -r '.riskScore')

if [ "$CRITICAL" -gt 0 ]; then
  curl -X POST $SLACK_WEBHOOK_URL \
    -H 'Content-Type: application/json' \
    -d '{
      "text": "🚨 CRITICAL: Security Scan Alert",
      "attachments": [{
        "color": "danger",
        "fields": [
          {"title": "Critical Issues", "value": "'$CRITICAL'", "short": true},
          {"title": "High Issues", "value": "'$HIGH'", "short": true},
          {"title": "Risk Score", "value": "'$RISK_SCORE'/10", "short": true}
        ]
      }]
    }'
fi
```

---

## Troubleshooting

### Common Issues

**Scan takes too long**
```bash
# Use quick scan instead
{
  "scanType": "QUICK_SCAN",
  "maxDepth": 1
}

# Or reduce depth
{
  "scanType": "FULL_SCAN",
  "maxDepth": 2  # Default is 3
}
```

**Too many false positives**
```bash
# Check scan evidence
curl -X GET "http://localhost:8080/api/scans/$SCAN_ID/vulnerabilities" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.[] | {title, evidence, confidence}'

# Vulnerabilities with confidence < 70% may be false positives
```

**Can't access protected endpoints**
```bash
# Future feature: Add authentication config
{
  "targetId": 1,
  "scanType": "FULL_SCAN",
  "authConfig": {
    "type": "JWT",
    "loginUrl": "/api/auth/login",
    "username": "test@example.com",
    "password": "testpass"
  }
}
```

---

## Best Practices

### 1. Scan Frequency
- **Development**: Every commit (Quick Scan)
- **Staging**: Daily (Full Scan)
- **Production**: Weekly (Full Scan)

### 2. Priority Handling
```bash
# Get only critical issues
curl -X GET "http://localhost:8080/api/scans/$SCAN_ID/vulnerabilities" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.[] | select(.severity == "CRITICAL")'

# Count by severity
curl -X GET "http://localhost:8080/api/scans/$SCAN_ID/vulnerabilities" \
  -H "Authorization: Bearer $TOKEN" \
  | jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### 3. Trend Analysis
```bash
# Get last 10 scans for a target
curl -X GET "http://localhost:8080/api/scans/target/$TARGET_ID" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.[:10] | map({date: .createdAt, critical: .criticalCount, riskScore: .riskScore})'

# Track improvement
# Before: riskScore: 7.8, critical: 2
# After fix: riskScore: 4.2, critical: 0
# Improvement: 46% risk reduction
```

---

## Production Deployment

### Environment Variables

```bash
# Database
export DATABASE_URL=jdbc:postgresql://localhost:5432/vulnscanner
export DATABASE_USERNAME=vulnscanner
export DATABASE_PASSWORD=secure_password

# JWT Secret (generate with: openssl rand -base64 64)
export JWT_SECRET=your_256_bit_secret_here

# Scanner Configuration
export SCANNER_MAX_CONCURRENT=10
export SCANNER_TIMEOUT=300
export SCANNER_USER_AGENT=VulnScanner-Pro/1.0

# Email (optional)
export MAIL_HOST=smtp.gmail.com
export MAIL_USERNAME=alerts@company.com
export MAIL_PASSWORD=app_password
```

### Docker Deployment

```bash
# Build
docker build -t vulnscanner-pro .

# Run
docker run -d \
  -p 8080:8080 \
  -e DATABASE_URL=$DATABASE_URL \
  -e JWT_SECRET=$JWT_SECRET \
  --name vulnscanner \
  vulnscanner-pro
```

---

For more examples, see:
- README.md
- ENTERPRISE_FEATURES.md
- API Documentation at /swagger-ui.html (if enabled)
