# 🛡️ Mini-SOAR: Automated Threat Intelligence Platform

Mini-SOAR is a lightweight Security Orchestration, Automation, and Response (SOAR) tool designed for SOC analysts to quickly triage IP addresses and file hashes. It automates threat intelligence lookups, saves scan history, and sends real-time alerts to Discord.

## 🚀 Features
- **Threat Intel Lookups:** Integrated with VirusTotal and AbuseIPDB APIs.
- **Automated Alerts:** Discord webhook integration for high-risk indicators.
- **Persistent Database:** SQLite database to store scan history (Docker volume mapped).
- **Interactive Dashboard:** Hacker-themed frontend UI to scan IPs/Hashes and view recent history.
- **Fully Containerized:** Docker and Docker Compose setup for easy deployment.
- **CI/CD Pipeline:** GitHub Actions for automated syntax checks on every push.

## 🏗️ Architecture
- **Frontend:** HTML, CSS, JavaScript (served via Nginx)
- **Backend:** Python, FastAPI, SQLAlchemy
- **Database:** SQLite
- **Automation:** Python scripts with Discord Webhooks

## 🛠️ How to Run Locally
1. Clone the repo: `git clone https://github.com/MDTahaZaki/mini-soar.git`
2. Create a `.env` file in the root directory:
   ```env
   VT_API_KEY=your_virustotal_key
   ABUSE_API_KEY=your_abuseipdb_key
   DISCORD_WEBHOOK_URL=your_discord_webhook
