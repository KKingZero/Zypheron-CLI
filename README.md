# Zypheron ⚡

An AI-powered cybersecurity assistant designed for penetration testers, red team operators, and security researchers. Features a ChatGPT-like interface with specialized tools for threat analysis, penetration testing, and AI-powered security assessments.

## 🔧 Quick Start

### Local Development (Auto-Setup)
```bash
# Clone and run locally with full access (no authentication required)
git clone https://github.com/yourusername/zypheron.git
cd zypheron
npm install
npm run dev
```
**🎯 Localhost automatically grants full access to all features!**

### Self-Hosted (Windows & Ubuntu)

Run everything locally with backend, frontend, and simple microservices.

Windows (PowerShell or CMD):
```bash
start-zypheron.bat
```

Ubuntu/Linux:
```bash
chmod +x start-zypheron.sh
./start-zypheron.sh
```

Docker (Windows or Ubuntu):
```bash
# Windows PowerShell
./start-docker.ps1

# Windows CMD
start-docker.bat

# Ubuntu/Linux
chmod +x start-docker.sh
./start-docker.sh
```

Notes:
- Dev scripts use simple Node services (no Python/Rust/C++/Go toolchains required).
- Docker path runs full stack with containers; ensure Docker is installed and running.

### Production Deployment
For production deployment with authentication and billing, see the [Setup Guide](#setup-guide) below.

## 🚀 Features

### Core AI Capabilities
- **Multi-Model Chat Interface**: Switch between GPT-4, Claude, Gemini, Grok, and GPT-3.5
- **Specialized Cybersecurity Prompts**: World-class penetration testing analyst system prompts
- **Context-Aware Analysis**: AI understands penetration test data and security contexts
- **Threat Level Assessment**: Automatic risk analysis with color-coded indicators

### Penetration Testing Suite
- **Comprehensive Network Analysis**: Complete IP classification, subnet analysis (ipconfig-style output)
- **Security Headers Analysis**: HTTP security headers evaluation with scoring
- **SSL/TLS Certificate Analysis**: Certificate and encryption strength assessment
- **DNS Enumeration**: Complete DNS record analysis and enumeration
- **Robots.txt Analysis**: Information disclosure detection
- **AI-Powered Security Assessment**: 3-paragraph expert analysis (vulnerabilities, attack vectors, remediation)

### Intelligence & Analysis
- **Threat Scanner**: Analyze IPs, URLs, and file hashes using VirusTotal and AbuseIPDB
- **IOC Analysis**: Comprehensive indicators of compromise lookup
- **Geolocation Data**: IP address geographic and organizational information
- **Recon Tools**: Terminal-ready commands and payloads for security testing

### User Experience
- **Professional UI**: Dark terminal theme with cybersecurity aesthetics
- **Fixed Sidebar Scrolling**: Independent scroll areas for optimal workflow
- **Export Capabilities**: Save penetration test results and conversation history
- **Real-time Features**: Typing indicators, syntax highlighting, responsive design

## 🛠️ Tech Stack

- **Frontend**: React 18 + TypeScript + Tailwind CSS + Vite
- **Backend**: Node.js + Express + TypeScript
- **Database**: Supabase (PostgreSQL) with comprehensive schema
- **Authentication**: Supabase Auth with Row Level Security
- **AI APIs**: OpenAI, Anthropic (Claude), Google (Gemini), xAI (Grok)
- **Security APIs**: VirusTotal, AbuseIPDB
- **UI**: Modern ChatGPT-inspired interface with terminal styling

## 📁 Project Structure

```
CobraAI/
├── frontend/              # React + TypeScript application
│   ├── src/
│   │   ├── components/    # UI components (ChatLayout, PentestPanel)
│   │   ├── contexts/      # React contexts for state management
│   │   ├── pages/         # Main application pages
│   │   └── utils/         # Utility functions and helpers
├── backend/               # Node.js + Express API server
│   ├── src/
│   │   ├── routes/        # API routes (chat, pentest, threat, auth)
│   │   └── server.ts      # Express server configuration
├── database/              # Supabase database schema and migrations
│   ├── schema-fixed.sql   # Complete database schema
│   └── fix-warnings.sql   # Security improvements
├── scripts/               # Setup and deployment scripts
└── package.json          # Root workspace configuration
```

## 🔧 Quick Setup

### Prerequisites
- Node.js 18+ and npm
- Supabase account (free tier available)
- API Keys for:
  - **OpenAI API** (required for AI functionality)
  - **VirusTotal API** (optional, for threat intelligence)
  - **AbuseIPDB API** (optional, for IP reputation)
  - **Additional AI models** (optional: Claude, Gemini, Grok)

### Installation

1. **Clone and install dependencies**:
   ```bash
   git clone https://github.com/KKingZero/Cobra-AI.git
   cd CobraAI
   npm run install:all
   ```

2. **Set up Supabase database**:
   - Create a new Supabase project at [supabase.com](https://supabase.com)
   - Go to SQL Editor and run the contents of `database/schema-fixed.sql`
   - Copy your project URL and API keys

3. **Configure environment variables**:
   
   **Backend** `backend/.env`:
   ```env
   # Supabase Configuration
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_ANON_KEY=your_supabase_anon_key
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   
   # AI Model API Keys
   OPENAI_API_KEY=sk-your_openai_api_key
   ANTHROPIC_API_KEY=your_claude_key_here          # Optional
   GOOGLE_API_KEY=your_gemini_key_here             # Optional
   XAI_API_KEY=your_grok_key_here                  # Optional
   
   # Threat Intelligence APIs (Optional)
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   
   # Server Configuration
   PORT=3001
   NODE_ENV=development
   ```
   
   **Frontend** `frontend/.env`:
   ```env
   # API Configuration
   VITE_API_URL=http://localhost:3001
   
   # Supabase Configuration
   VITE_SUPABASE_URL=https://your-project.supabase.co
   VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
   ```

4. **Start development servers**:
   ```bash
   npm run dev
   ```

The application will be available at:
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:3001

## 🎯 Usage Guide

### 1. Chat Interface
- **Ask cybersecurity questions**: Get expert advice on tools, techniques, and methodologies
- **Request tool recommendations**: Receive specific commands for Nmap, Burp Suite, Nikto, etc.
- **Generate payloads**: Create custom scripts and commands for security testing
- **Switch AI models**: Choose between different models for varied analysis styles

### 2. Penetration Testing
- **Click "Pen Test"** in the chat header to open the testing panel
- **Configure target and tests**: Select website and security assessment types
- **Review comprehensive results**: Network analysis, security headers, SSL/TLS, DNS, robots.txt
- **Get AI analysis**: Click "Analyze with AI" for expert security assessment

### 3. Threat Intelligence
- **Navigate to Threat Scanner**: Analyze IPs, URLs, domains, and file hashes
- **View threat levels**: Color-coded risk indicators with detailed analysis
- **Access geolocation data**: Geographic and organizational information
- **Export results**: Save analysis data for documentation

### 4. Security Tools
- **Visit Recon Tools**: Access pre-configured security commands
- **Copy to clipboard**: Ready-to-use commands with dynamic target substitution
- **Command categories**: Network scanning, web testing, enumeration, exploitation

## 🔐 Key Security Features

### Penetration Testing Capabilities
- **Network Discovery**: Complete IP analysis with subnet and routing information
- **Security Assessment**: Automated evaluation of security headers, SSL/TLS, DNS
- **Vulnerability Analysis**: AI-powered assessment with attack vectors and remediation
- **Professional Reporting**: Detailed results with executive summaries

### AI-Powered Analysis
- **Expert Prompts**: World-class penetration testing analyst system prompts
- **3-Paragraph Assessment**: Structured analysis format covering vulnerabilities, attacks, and fixes
- **Context Awareness**: AI understands security data and provides relevant recommendations
- **Multi-Model Support**: Choose the best AI model for your specific analysis needs

### Threat Intelligence
- **Real-time IOC Analysis**: Live threat intelligence from multiple sources
- **IP Reputation**: Geographic location, ISP information, and abuse history
- **Domain Analysis**: DNS records, SSL certificates, and security headers
- **File Hash Lookup**: Malware detection and analysis

## 🚧 Roadmap & Future Features

### Advanced Penetration Testing
- [ ] **Port Scanning Integration**: Nmap integration with visual results
- [ ] **Subdomain Enumeration**: Automated discovery with DNS analysis
- [ ] **Directory Discovery**: Web application directory and file enumeration
- [ ] **Vulnerability Scanning**: Integration with popular security scanners
- [ ] **Custom Payload Generation**: AI-assisted exploit and payload creation

### Enhanced AI Capabilities
- [ ] **Custom Model Training**: Fine-tuned models for cybersecurity tasks
- [ ] **Automated Report Generation**: Executive and technical report creation
- [ ] **Threat Hunting Assistance**: Query generation for SIEM and log analysis
- [ ] **Incident Response Guidance**: Step-by-step incident handling procedures
- [ ] **Compliance Mapping**: Framework compliance checking (NIST, ISO 27001, etc.)

### Team Collaboration
- [ ] **Multi-user Workspaces**: Shared penetration testing projects
- [ ] **Real-time Collaboration**: Live editing and commenting on assessments
- [ ] **Role-based Access Control**: Granular permissions for team members
- [ ] **Team Analytics**: Performance metrics and reporting dashboards
- [ ] **Project Templates**: Standardized assessment templates

### Integration & Automation
- [ ] **CI/CD Security Integration**: Automated security scanning in pipelines
- [ ] **SIEM Integration**: Real-time alerting and log analysis
- [ ] **API Webhooks**: Custom integrations with security tools
- [ ] **Scheduled Assessments**: Automated recurring security tests
- [ ] **Third-party Tool Integration**: Metasploit, Burp Suite, OWASP ZAP

## ⚠️ Important Security Notes

### Ethical Use Requirements
- ✅ **Only test systems you own** or have explicit written authorization to test
- ✅ **Follow responsible disclosure** practices for discovered vulnerabilities
- ✅ **Respect rate limits** and avoid overwhelming target systems
- ✅ **Document all activities** for audit and compliance purposes
- ✅ **Comply with local laws** and regulations regarding security testing

### API Key Security
- ✅ Never commit API keys to version control
- ✅ Use environment variables for all sensitive configuration
- ✅ Regularly rotate API keys and monitor usage
- ✅ Implement proper access controls in production environments

## 🚀 Setup Guide

### Development Mode (Localhost)

**🔧 Zero Configuration Required!**
```bash
git clone https://github.com/yourusername/zypheron.git
cd zypheron
npm install
npm run dev
```

**What you get instantly:**
- ✅ Full access to all features
- ✅ No login required
- ✅ Unlimited tokens
- ✅ All premium features unlocked
- ✅ Developer tools enabled

**To disable localhost access:**
```typescript
// frontend/src/utils/devMode.ts
export const DEV_MODE_ENABLED = false  // Change to false
```

### Production Deployment

#### 1. 📊 Database Setup (Supabase)
```sql
-- Copy and paste this into Supabase SQL Editor
-- File: database/supabase-setup-fixed.sql
```
- Create Supabase project
- Run `database/supabase-setup-fixed.sql` in SQL Editor
- Get your Supabase URL and keys

#### 2. 🔐 Environment Configuration
```bash
# Frontend (.env)
VITE_SUPABASE_URL=your_supabase_project_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
VITE_API_URL=http://localhost:3001

# Backend (.env)
SUPABASE_URL=your_supabase_project_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
OPENAI_API_KEY=your_openai_key
STRIPE_SECRET_KEY=your_stripe_secret_key
```

#### 3. 💳 Stripe Setup (Optional)
- Create Stripe account
- Get publishable and secret keys
- Configure buy button IDs in `frontend/src/pages/Billing.tsx`

#### 4. 🚀 Deployment
```bash
# Frontend (Netlify/Vercel)
npm run build
# Deploy dist/ folder

# Backend (Railway/Heroku/VPS)
npm install
npm run build
npm start
```

### Developer Access

**🔧 shabblezam@gmail.com** automatically gets:
- ✅ Enterprise plan access
- ✅ Unlimited tokens  
- ✅ Developer mode badges
- ✅ Bypass all restrictions

**To add more developer emails:**
```sql
-- Update in database/supabase-setup-fixed.sql
IF new.email IN ('shabblezam@gmail.com', 'your-email@domain.com') THEN
```

### Configuration Options

**🎛️ Development Mode Controls:**
```typescript
// frontend/src/utils/devMode.ts
export const DEV_CONFIG = {
  enableLocalhostAccess: true,    // Auto-access on localhost
  enableDeveloperMode: true,      // Dev features enabled
  bypassAuthentication: true,     // Skip login locally
  unlimitedAccess: true          // Unlimited everything
}
```

**🔧 Feature Flags:**
- Set `DEV_MODE_ENABLED = false` to disable all dev features
- Perfect for production deployments
- Localhost detection works automatically

## 📚 Documentation

- **[SETUP.md](SETUP.md)**: Comprehensive setup and deployment guide
- **Database Schema**: Complete documentation in `database/` directory
- **API Documentation**: RESTful API endpoints and usage examples
- **Security Guidelines**: Best practices for ethical penetration testing

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**⚠️ Legal Disclaimer**: Zypheron is intended exclusively for authorized security testing and educational purposes. Users are solely responsible for ensuring compliance with applicable laws, regulations, and organizational policies. Always obtain explicit written authorization before conducting penetration tests on any systems. Unauthorized access to computer systems is illegal and unethical.

**🐍 Built for Security Professionals**: Zypheron empowers cybersecurity teams with AI-enhanced capabilities while maintaining the highest standards of ethical hacking practices. 