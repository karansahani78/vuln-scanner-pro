# Getting Started with VulnScanner Pro

## Welcome! 👋

This guide will help you get VulnScanner Pro up and running in just a few minutes.

## Step 1: Prerequisites Check

Make sure you have:
- ☑️ Java 17 or higher installed
- ☑️ Maven 3.8+ installed
- ☑️ Your favorite IDE (IntelliJ IDEA, Eclipse, or VS Code)

### Check Your Java Version
```bash
java -version
```
You should see something like: `openjdk version "17.0.x"`

### Check Your Maven Version
```bash
mvn -version
```

## Step 2: Build the Project

```bash
cd vuln-scanner-pro
mvn clean install
```

This will:
1. Download all dependencies
2. Compile the code
3. Run tests
4. Create the application JAR

**Expected output:** `BUILD SUCCESS`

## Step 3: Run the Application

```bash
mvn spring-boot:run
```

**You should see:**
```
  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/

VulnScanner Pro started on port 8080
```

## Step 4: Access the Application

### H2 Database Console (Development)
- **URL:** http://localhost:8080/h2-console
- **JDBC URL:** `jdbc:h2:mem:vulnscanner`
- **Username:** `sa`
- **Password:** (leave blank)

## Step 5: Test the API

### Option A: Use cURL

1. **Register a user:**
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "admin123",
    "fullName": "Admin User"
  }'
```

2. **Login to get a token:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Save the token from the response!** You'll need it for the next steps.

3. **Create a target to scan:**
```bash
curl -X POST http://localhost:8080/api/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "name": "Test Website",
    "url": "https://httpbin.org",
    "type": "WEB_APPLICATION",
    "description": "Test target for scanning"
  }'
```

4. **Start a scan:**
```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "targetId": 1,
    "scanType": "QUICK_SCAN",
    "checkSSL": true,
    "maxDepth": 2
  }'
```

5. **Check scan results:**
```bash
curl -X GET http://localhost:8080/api/scans/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Option B: Use Postman

1. Import the file: `VulnScanner-API.postman_collection.json`
2. Set up an environment variable `token` after login
3. Run the requests in order

## Step 6: Understanding the Workflow

```
1. Register/Login → Get JWT Token
2. Create Target → Add website to scan
3. Start Scan → Initiate vulnerability scan
4. Check Results → View vulnerabilities found
```

## Common Issues & Solutions

### Issue: Port 8080 already in use
**Solution:** Change the port in `application.properties`:
```properties
server.port=8081
```

### Issue: Database connection error
**Solution:** For development, H2 is configured by default. No setup needed!

### Issue: Redis connection error
**Solution:** Redis is optional. Comment out Redis config in `application.properties`:
```properties
# spring.data.redis.host=localhost
# spring.data.redis.port=6379
```

## Next Steps

Once you're comfortable:

1. **Customize Scanners:** Add new vulnerability scanners in `scanner/` package
2. **Configure Production DB:** Switch to PostgreSQL for production
3. **Add More Features:** Email notifications, scheduled scans, PDF reports
4. **Deploy:** Package and deploy to your server

## Project Structure

```
vuln-scanner-pro/
├── src/main/java/com/security/vulnscanner/
│   ├── config/          # Security and app configuration
│   ├── controller/      # REST API endpoints
│   ├── dto/             # Data Transfer Objects
│   ├── model/           # Database entities
│   ├── repository/      # Database repositories
│   ├── scanner/         # Vulnerability scanners
│   ├── security/        # JWT and auth logic
│   └── service/         # Business logic
├── src/main/resources/
│   └── application.properties
└── pom.xml              # Maven dependencies
```

## Need Help?

- 📖 Check the full `README.md`
- 🐛 Report issues on GitHub
- 💬 Join our community forum
- 📧 Email: support@vulnscanner.pro

## Happy Scanning! 🔒

Remember: Only scan applications you own or have permission to test!

---
**Security Note:** This tool is for authorized security testing only. Unauthorized scanning is illegal and unethical.
