# VulnScanner Pro - Free & Open Source

> Enterprise-grade web application security scanner. 100% free. No limits.

[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://openjdk.java.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.1-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 🎯 What is VulnScanner Pro?

VulnScanner Pro is a free, open-source vulnerability scanning platform that helps developers and security professionals identify security issues in web applications. Think Burp Suite or OWASP ZAP, but simpler and free.

### Key Features

✅ **Comprehensive Scanning**
- SQL Injection detection
- XSS vulnerability scanning
- Security header analysis
- SSL/TLS configuration check
- Technology stack detection
- API security testing

✅ **Professional Reporting**
- Developer-focused technical reports
- Executive summaries
- Compliance reports (OWASP, CWE mapping)
- Markdown export

✅ **Enterprise Security**
- Multi-user support
- Secure multi-tenancy
- JWT authentication
- Ownership validation on all operations

✅ **High Quality**
- <15% false positive rate
- Analytics cookie filtering
- Smart vulnerability classification
- Accurate risk scoring

✅ **Developer Friendly**
- RESTful API
- Complete API documentation
- Easy deployment
- Docker support (coming soon)

---

## 🚀 Quick Start

### Prerequisites

- Java 17 or higher
- PostgreSQL 12+
- Maven 3.6+

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/vulnscanner-pro.git
cd vulnscanner-pro
```

2. **Create PostgreSQL database**
```bash
createdb vulnscanner
```

3. **Configure application**
```bash
# Edit src/main/resources/application.properties
spring.datasource.url=jdbc:postgresql://localhost:5432/vulnscanner
spring.datasource.username=your_username
spring.datasource.password=your_password
```

4. **Build and run**
```bash
mvn clean install
mvn spring-boot:run
```

5. **Access the API**
```
http://localhost:8080
```

---

## 📖 Usage

### 1. Register a User

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "fullName": "Alice Security"
  }'
```

### 2. Login

```bash
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePass123!"}' \
  | jq -r '.token')
```

### 3. Add a Target

```bash
curl -X POST http://localhost:8080/api/targets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Website",
    "url": "https://example.com",
    "description": "Production website"
  }'
```

### 4. Start a Scan

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targetId": 1,
    "scanType": "COMPREHENSIVE",
    "includeSubdomains": true,
    "checkSSL": true,
    "detectCMS": true
  }'
```

### 5. View Results

```bash
# Get scan status
curl http://localhost:8080/api/scans/1 \
  -H "Authorization: Bearer $TOKEN"

# Get vulnerabilities
curl http://localhost:8080/api/scans/1/vulnerabilities \
  -H "Authorization: Bearer $TOKEN"

# Download report
curl http://localhost:8080/api/reports/1/developer \
  -H "Authorization: Bearer $TOKEN" \
  -o report.md
```

---

## 🏗️ Architecture

### Tech Stack

**Backend:**
- Spring Boot 3.2.1
- Spring Security (JWT)
- Spring Data JPA
- PostgreSQL
- Java HTTP Client
- Lombok

**Scanners:**
- SQL Injection Scanner
- XSS Scanner
- Security Headers Scanner
- API Security Scanner
- Technology Detector

**Security:**
- Multi-tenant isolation
- Ownership validation
- JWT authentication
- Secure password hashing (BCrypt)

### Project Structure

```
src/main/java/com/security/vulnscanner/
├── controller/          # REST API endpoints
├── service/            # Business logic
├── scanner/            # Vulnerability scanners
├── model/              # Data entities
├── repository/         # Database access
├── security/           # JWT & authentication
├── dto/                # Data transfer objects
├── exception/          # Custom exceptions
└── config/             # Spring configuration
```

---

## 📊 API Documentation

See [API_EXAMPLES.md](API_EXAMPLES.md) for complete API documentation with examples.

### Main Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/auth/register | POST | Create new user |
| /api/auth/login | POST | Login and get JWT token |
| /api/targets | GET/POST | Manage scan targets |
| /api/scans | POST | Start new scan |
| /api/scans/{id} | GET | Get scan details |
| /api/scans/{id}/vulnerabilities | GET | Get vulnerabilities |
| /api/reports/{id}/developer | GET | Download developer report |
| /api/reports/{id}/executive | GET | Download executive report |

---

## 🔒 Security Features

### Multi-Tenant Security
- Each user can only access their own data
- Ownership validation on all operations
- Returns proper HTTP status codes (403, 404)

### Vulnerability Detection
- SQL Injection (time-based, error-based, boolean-based)
- Cross-Site Scripting (reflected, stored)
- Missing security headers
- Insecure cookies (session cookies only)
- SSL/TLS misconfigurations
- API security issues

### False Positive Reduction
- Analytics cookie filtering (Google Analytics, Facebook Pixel, etc.)
- Smart cookie classification (only flags session cookies)
- Context-aware vulnerability validation
- <15% false positive rate

---

## 🛠️ Configuration

### Database Configuration

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/vulnscanner
spring.datasource.username=postgres
spring.datasource.password=your_password
spring.jpa.hibernate.ddl-auto=update
```

### Security Configuration

```properties
jwt.secret=your-256-bit-secret-key-here
jwt.expiration=86400000
```

### Scanner Configuration

```properties
scanner.timeout-seconds=300
scanner.max-concurrent-per-target=1
scanner.user-agent=VulnScanner-Pro/3.0
```

---

## 🎨 Building the Frontend

See [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md) for complete frontend development guide.

### Quick Start

```bash
# Option 1: Use the AI prompt
# Give FRONTEND_GUIDE.md to Claude, ChatGPT, or Cursor

# Option 2: Manual setup
npm create vite@latest vulnscanner-frontend -- --template react-ts
cd vulnscanner-frontend
npm install react-router-dom @tanstack/react-query axios
npm install lucide-react recharts tailwindcss
npx shadcn-ui@latest init
npm run dev
```

---

## 📝 Development

### Running Tests

```bash
mvn test
```

### Building for Production

```bash
mvn clean package
java -jar target/vuln-scanner-pro-1.0.0.jar
```

### Database Migrations

First time setup:
```sql
-- The application will auto-create tables
-- Recommended indexes for production:
CREATE INDEX idx_scan_target_status ON scans(target_id, status);
CREATE INDEX idx_target_user ON targets(user_id);
CREATE INDEX idx_vulnerability_scan ON vulnerabilities(scan_id);
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Java naming conventions
- Use Lombok for boilerplate code
- Write meaningful comments for business logic
- Add tests for new features

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by Burp Suite, OWASP ZAP, and Nessus
- Built with Spring Boot and love for security
- Special thanks to the open-source community

---

## 📞 Support

- **Documentation**: See `/docs` folder
- **Issues**: [GitHub Issues](https://github.com/yourusername/vulnscanner-pro/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/vulnscanner-pro/discussions)

---

## 🗺️ Roadmap

### Current Version (v3.0)
- ✅ Core vulnerability scanning
- ✅ Multi-user support
- ✅ Professional reporting
- ✅ Low false positives

### Future Releases
- 🔄 Scheduled scanning
- 🔄 Slack/Discord notifications
- 🔄 Docker deployment
- 🔄 Plugin system
- 🔄 Machine learning for vulnerability detection
- 🔄 REST API versioning
- 🔄 GraphQL support

---

## ⭐ Star History

If you find this project useful, please consider giving it a star!

---

**Made with ❤️ by the security community, for the security community.**
