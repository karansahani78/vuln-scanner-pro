# Frontend Development Prompt - VulnScanner Pro (Free Version)

## 🎯 Project Overview

You are building the **frontend web application** for **VulnScanner Pro** - a free, open-source vulnerability scanning platform similar to Burp Suite or OWASP ZAP, with professional reporting and enterprise security features.

The **backend API is complete and production-ready**. Your job is to create a modern, secure, and user-friendly frontend that connects to this API.

---

## 📋 Core Requirements

### Technology Stack
- **Framework**: React 18+ with TypeScript
- **Styling**: Tailwind CSS + shadcn/ui components
- **State Management**: React Query (TanStack Query) for API calls
- **Routing**: React Router v6
- **Auth**: JWT tokens (stored in localStorage)
- **Charts**: Recharts for vulnerability graphs
- **Icons**: Lucide React
- **Build Tool**: Vite

### Design System
- **Style**: Modern, professional, security-focused
- **Color Palette**:
  - Primary: Indigo/Blue (trust, security)
  - Danger: Red (critical vulnerabilities)
  - Warning: Orange (high severity)
  - Success: Green (secure, completed scans)
  - Background: Light/Dark mode support
- **Typography**: Inter or Poppins
- **Components**: Use shadcn/ui for consistency

---

## 🔐 Backend API Documentation

### Base URL
```
http://localhost:8080/api
```

### Authentication Endpoints

**POST /auth/register**
```json
Request:
{
  "username": "string",
  "email": "string",
  "password": "string",
  "fullName": "string"
}

Response:
{
  "message": "User registered successfully",
  "userId": 1
}
```

**POST /auth/login**
```json
Request:
{
  "username": "string",
  "password": "string"
}

Response:
{
  "token": "jwt_token_here",
  "username": "string",
  "email": "string"
}
```

### Target Endpoints

**POST /targets**
```json
Request:
{
  "name": "string",
  "url": "https://example.com",
  "description": "string"
}

Response:
{
  "id": 1,
  "name": "string",
  "url": "string",
  "description": "string",
  "createdAt": "2026-01-17T..."
}
```

**GET /targets**
Returns array of user's targets

**DELETE /targets/{id}**
Deletes a target

### Scan Endpoints

**POST /scans**
```json
Request:
{
  "targetId": 1,
  "scanType": "COMPREHENSIVE",  // or "QUICK"
  "includeSubdomains": true,
  "checkSSL": true,
  "detectCMS": true,
  "scanPorts": false,
  "maxDepth": 3
}

Response:
{
  "scanId": 1,
  "status": "PENDING",
  "message": "Scan started successfully"
}
```

**GET /scans/{id}**
```json
Response:
{
  "id": 1,
  "status": "COMPLETED",  // PENDING, RUNNING, COMPLETED, FAILED
  "scanType": "COMPREHENSIVE",
  "startedAt": "2026-01-17T14:00:00",
  "completedAt": "2026-01-17T14:05:23",
  "durationSeconds": 323,
  "totalVulnerabilities": 15,
  "criticalCount": 2,
  "highCount": 5,
  "mediumCount": 6,
  "lowCount": 2,
  "infoCount": 0,
  "riskScore": 7.8,
  "target": {
    "id": 1,
    "name": "Production Site",
    "url": "https://example.com"
  }
}
```

**GET /scans/{id}/vulnerabilities**
Returns array of vulnerabilities

**PUT /scans/vulnerabilities/{id}/false-positive**
Mark vulnerability as false positive

**PUT /scans/vulnerabilities/{id}/resolved**
Mark vulnerability as resolved

### Report Endpoints

**GET /reports/{scanId}/developer**
Returns: Markdown developer report

**GET /reports/{scanId}/executive**
Returns: Markdown executive summary

**GET /reports/{scanId}/compliance**
Returns: Markdown compliance report

---

## 📱 Required Pages & Features

### 1. Landing Page (Public)
**Route**: `/`

**Sections**:
- Hero: "Free Enterprise Security Scanning"
  - CTA: "Get Started Free" → Register
  - "View Demo" button
- Features grid:
  - 🔍 Comprehensive Security Scanning
  - ⚡ Fast 5-Minute Scans
  - 📊 Professional Reports
  - 🎯 Low False Positive Rate
  - 100% Free & Open Source
- Footer: Links, GitHub

### 2. Register/Login Pages
**Routes**: `/register`, `/login`

Simple, clean auth forms

### 3. Dashboard (Authenticated)
**Route**: `/dashboard`

**Sections**:
- Stats cards: Total Scans, Targets, Critical Vulns, Risk Score
- "New Scan" button
- Recent scans table
- Vulnerability breakdown chart
- Recent activity feed

### 4. Targets Page
**Route**: `/targets`

- Grid/list of targets
- "Add Target" button
- Edit/Delete/Scan actions

### 5. New Scan Page
**Route**: `/scans/new`

**Form**:
- Select Target
- Scan Type (QUICK/COMPREHENSIVE)
- Advanced options (collapsible)
- "Start Scan" button

### 6. Scan Detail Page
**Route**: `/scans/:id`

**Show**:
- Scan status & metadata
- Risk score (big number)
- Vulnerability counts by severity
- Vulnerabilities table (filterable, sortable)
- Download report buttons

**Real-time Updates**:
- Poll every 5s if status is RUNNING
- Show progress indicator

### 7. All Scans Page
**Route**: `/scans`

- Filterable scans list
- Sort by date, risk score
- Pagination

### 8. Settings Page
**Route**: `/settings`

**Tabs**:
- Profile (edit name, email, password)
- Preferences (theme, notifications)

---

## 🎨 UI/UX Requirements

### Color Coding (Severity)
```
CRITICAL: Red background, white text
HIGH:     Orange background
MEDIUM:   Yellow background
LOW:      Blue background
INFO:     Gray background
```

### Status Badges
```
PENDING:   Blue, pulse animation
RUNNING:   Yellow, loading spinner
COMPLETED: Green, checkmark
FAILED:    Red, X icon
```

### Empty States
- No scans: "Start your first scan"
- No targets: "Add your first target"
- No vulnerabilities: "All clear! 🎉"

---

## 🚀 Example Component Structure

```
src/
├── components/
│   ├── ui/              # shadcn/ui components
│   ├── layout/
│   │   ├── Header.tsx
│   │   ├── Sidebar.tsx
│   │   └── Footer.tsx
│   ├── scans/
│   │   ├── ScanCard.tsx
│   │   ├── ScanStatusBadge.tsx
│   │   ├── VulnerabilityTable.tsx
│   │   └── RiskScoreGauge.tsx
│   └── targets/
│       ├── TargetCard.tsx
│       └── AddTargetModal.tsx
├── pages/
│   ├── Landing.tsx
│   ├── Login.tsx
│   ├── Register.tsx
│   ├── Dashboard.tsx
│   ├── Targets.tsx
│   ├── NewScan.tsx
│   ├── ScanDetail.tsx
│   ├── AllScans.tsx
│   └── Settings.tsx
├── hooks/
│   ├── useAuth.ts
│   ├── useScans.ts
│   └── useTargets.ts
├── lib/
│   ├── api.ts
│   └── utils.ts
└── types/
    ├── scan.ts
    ├── target.ts
    └── vulnerability.ts
```

---

## 🔐 Security Requirements

- Store JWT in localStorage
- Auto-logout on 401
- HTTPS-only in production
- Input validation
- XSS prevention

---

## 📦 Setup Instructions

```bash
# Create project
npm create vite@latest vulnscanner-frontend -- --template react-ts

# Install dependencies
npm install react-router-dom @tanstack/react-query axios
npm install lucide-react recharts
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

# Add shadcn/ui
npx shadcn-ui@latest init
npx shadcn-ui@latest add button card input table badge

# Start dev server
npm run dev
```

---

## 🎯 Success Criteria

### Functional
- ✅ All API endpoints integrated
- ✅ Authentication working
- ✅ Scans can be created and viewed
- ✅ Reports can be downloaded
- ✅ Real-time scan status updates

### UX
- ✅ <2s page load
- ✅ Mobile responsive
- ✅ Clear error messages
- ✅ Loading states everywhere
- ✅ Smooth animations

---

## 💡 Design Inspiration

- Stripe Dashboard (clean, professional)
- Vercel Dashboard (modern, fast)
- GitHub UI (developer-friendly)
- OWASP ZAP (security tool reference)

---

**Build a beautiful, free-to-use security scanner that developers will love!** 🚀🔒
