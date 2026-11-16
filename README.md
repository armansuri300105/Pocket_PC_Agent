<div align="center">
  <p align="center">
  <img
  src="https://res.cloudinary.com/do9m8kc0b/image/upload/f_auto,q_auto,w_1200/v1794388821/er9antbqxpgfpeamaag6.png"
  alt="PocketPC Agent Banner"
  width="100%"
/>
</p>

  <h1>PocketPC Agent</h1>
  <p><b>An autonomous, zero-token Telegram agent for secure PC management, local dev environments, and anti-theft surveillance.</b></p>

  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/aiogram-v3.x-0088cc?style=flat-square&logo=telegram" alt="aiogram v3">
  <img src="https://img.shields.io/badge/Tests-107%2F107%20Passing-brightgreen?style=flat-square" alt="Tests: 107/107 Passing">
  <a href="https://github.com/armansuri300105/Pocket_PC_Agent/stargazers"><img src="https://img.shields.io/github/stars/armansuri300105/Pocket_PC_Agent?style=flat-square&color=blue" alt="Stars"></a>
  <a href="https://github.com/armansuri300105/Pocket_PC_Agent/network/members"><img src="https://img.shields.io/github/forks/armansuri300105/Pocket_PC_Agent?style=flat-square" alt="Forks"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License: MIT"></a>
</div>

<br/>

## 🚀 The Vision
Managing localhost servers, proxying ports, and monitoring your PC shouldn't require you to be glued to your desk. **PocketPC Agent** bridges your mobile phone to your Windows PC via Telegram, combining a sub-5ms deterministic command router with an LLM-powered AI Planner (LangGraph / Ollama / OpenAI) for natural language computer control.

## ⚡ Core Architecture
*   **0-Token Fast Router:** Common commands (`/screenshot`, `/webcam`, `/locate`, `/status`, `/lockpc`) execute in under 5ms using deterministic regex matching, bypassing the LLM entirely to eliminate latency and save API tokens.
*   **4-Tier Permission Gate:** Destructive actions (killing processes, deleting files) require inline Telegram button approvals (Tier 2) or a secure 4-digit PIN challenge (Tier 3). Catastrophic OS commands (`format`, `rmdir /s /q`) are hard-blocked (Tier 4).
*   **30-Day Undo Sandbox:** The `SmartFileResolver` intercepts file deletions, moving them to a hidden `.undo_storage` vault so you can recover them instantly with `/undo`.
*   **Developer Services & Cloudflare Tunnels:** Start, stop, and monitor developer services (FastAPI, Vite, Next.js, Node) defined in `services.json`, and expose local ports to public HTTPS URLs via Cloudflare Quick Tunnels.
*   **Anti-Theft Surveillance:** Runs headlessly via `pythonw.exe` on boot. Remotely lock your PC, capture silent webcam intruder photos, take targeted window or multi-window screenshots, and triangulate location via nearby Wi-Fi BSSIDs and IP geolocation.
*   **Pre-Flight Secret Scrubber:** Automatically detects and redacts API keys, bearer tokens, passwords, and `.env` credentials before any prompt reaches the LLM.

## 🛠️ Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/armansuri300105/Pocket_PC_Agent.git
cd Pocket_PC_Agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create Your Telegram Bot
Because the agent uses Owner-Only Middleware to drop unauthorized requests, you need a Bot Token and your personal Telegram ID.
1. Open Telegram and search for **@BotFather**.
2. Send `/newbot`, choose a name, and copy the **HTTP API Token** it generates for you.
3. Search for **@userinfobot** in Telegram and send `/start`. Copy your numerical `Id` (this is your Owner ID).

### 3. Configure Environment
Copy the example environment file and configure your credentials:
```bash
cp .env.example .env
```
Open `.env` and fill in:
* `TELEGRAM_BOT_TOKEN`: The token from @BotFather.
* `OWNER_TELEGRAM_ID`: Your numerical ID from @userinfobot.
* `SAFETY_PIN`: 4-digit PIN for Tier 3 destructive operations (e.g. `1234`).
* `ALLOWED_DIRS`: Semicolon-separated list of directories the agent is allowed to access.
* *(Optional)* Local services: Copy `services.example.json` to `services.json` to register your local projects.

### 4. Run the Agent
To run normally with interactive terminal output:
```bash
python main.py
```
To run **invisibly** in the background (stealth daemon):
```powershell
.\venv\Scripts\pythonw.exe main.py
```
To install as a persistent Windows Scheduled Task that auto-starts on logon and workstation unlock:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_autostart.ps1
```

## 🧪 Running Tests
PocketPC Agent includes a comprehensive test suite (107 unit and integration tests across 6 phases) covering permission gates, fast routing, directory jails, secret scrubbing, AI planner execution, and surveillance tools.

Run all tests:
```bash
pytest
```

Run with verbose output:
```bash
pytest -v
```

Run specific test suites:
```bash
pytest tests/test_phase1.py   # Config, directory jail, undo engine, audit database
pytest tests/test_phase2.py   # 4-Tier permission gate, fast router (<5ms), vitals
pytest tests/test_phase3.py   # Telegram gateway, Owner-Only lock, PIN approvals
pytest tests/test_phase4.py   # Pre-flight secret scrubber, skills & shortcuts
pytest tests/test_phase5.py   # Dev services, Cloudflare tunnels, keep-awake
pytest tests/test_phase6.py   # Surveillance, multi-screenshot, anti-theft & compound commands
```

On Windows with virtualenv:
```powershell
.\venv\Scripts\pytest -v
```

## 📱 Quick Commands Reference

| Command / Natural Phrasing | Description | Security Tier |
| :--- | :--- | :--- |
| 📸 `/screenshot` | Captures primary display screenshot | Tier 1 (Auto) |
| 📷 `/webcam` | Silently captures photo from webcam | Tier 1 (Auto) |
| 🪟 `screenshot of chrome` | Captures specific application window | Tier 1 (Auto) |
| 🪟 `all windows screenshot` | Captures album of all open taskbar windows | Tier 1 (Auto) |
| 📊 `/status` or `vitals` | Reports CPU, RAM, Disk, and Battery stats | Tier 1 (Auto) |
| 📍 `/locate` | Reports IP geolocation & nearby Wi-Fi BSSIDs | Tier 1 (Auto) |
| 🔒 `/lockpc` | Locks Windows workstation & clears clipboard | Tier 1 (Auto) |
| ☕ `/caffeinate 60` | Prevents PC sleep for N minutes (Win32 API) | Tier 1 (Auto) |
| 🔍 `/find <filename>` | Fuzzy searches files within `ALLOWED_DIRS` | Tier 1 (Auto) |
| ↩️ `/undo` | Restores last deleted or moved file | Tier 1 (Auto) |
| 📋 `/services` | Lists configured dev services & port status | Tier 1 (Auto) |
| 🚀 `start backend` | Spawns project service from `services.json` | Tier 2 (Button) |
| 🌐 `expose 3000` | Creates public HTTPS Cloudflare tunnel | Tier 2 (Button) |
| 🛑 `/stop` | Emergency kill switch & locks system | Tier 1 (Auto) |

## 🛡️ Security Invariants
This agent is built with local-first security as the primary engineering constraint:
*   **Owner-Only Middleware:** Drops all Telegram requests from unverified User IDs at the gateway level. No information or error message is returned to unauthorized users.
*   **Path Jail:** The `SmartFileResolver` restricts all file I/O strictly to `ALLOWED_DIRS` defined in your environment variables, preventing path traversal attacks (`../`).
*   **Deterministic Permission Gate:** Security tiers are enforced in deterministic Python code prior to tool execution. The LLM has zero authority to bypass security rules.
*   **Pre-Flight Secret Scrubbing:** Redacts credentials and keys before prompts are dispatched to LLM providers.
*   **Zero Direct Deletion:** Deleted files are never permanently unlinked directly; they are preserved in `.undo_storage/` with instant restoration via `/undo`.

## 🤝 Contributing
Contributions are welcome! Please ensure all pull requests pass the `pytest` regression suite before submission, especially regarding Permission Gate logic.
