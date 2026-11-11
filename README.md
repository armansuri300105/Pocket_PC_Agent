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

  <a href="https://github.com/armansuri300105/Pocket_PC_Agent/stargazers"><img src="https://img.shields.io/github/stars/armansuri300105/Pocket_PC_Agent?style=flat-square&color=blue" alt="Stars"></a>
  <a href="https://github.com/armansuri300105/Pocket_PC_Agent/network/members"><img src="https://img.shields.io/github/forks/armansuri300105/Pocket_PC_Agent?style=flat-square" alt="Forks"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License: MIT"></a>
</div>

<br/>

## 🚀 The Vision
Managing localhost servers, proxying ports, and monitoring your PC shouldn't require you to be glued to your desk. **PocketPC Agent** bridges your mobile phone to your Windows PC via Telegram, using an LLM-powered AI Planner backed by a lightning-fast deterministic router.

**[INSERT A 15-SECOND GIF HERE SHOWING YOU STARTING A SERVICE OR TAKING A SCREENSHOT FROM YOUR PHONE]**

## ⚡ Core Architecture
*   **0-Token Fast Router:** Common commands (`/screenshot`, `/locate`, `/status`) execute in under 5ms using regex, bypassing the LLM entirely to save API costs.
*   **4-Tier Permission Gate:** Destructive actions (killing processes, deleting files) require inline Telegram button approvals (Tier 2) or a secure PIN challenge (Tier 3).
*   **30-Day Undo Sandbox:** The `SmartFileResolver` intercepts file deletions, moving them to a hidden `.undo_storage` vault so you can recover them instantly with `/undo`.
*   **Anti-Theft Surveillance:** Runs headlessly via `pythonw.exe` on boot. Remotely lock your PC, capture silent webcam intruder snaps, and triangulate location via nearby Wi-Fi BSSIDs.

## 🛠️ Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/armansuri300105/Pocket_PC_Agent.git
cd Pocket_PC_Agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment
Copy the example environment file and add your tokens:
```bash
cp .env.example .env
```

### 3. Run the Agent
To run normally with terminal output:
```bash
python main.py
```
To run **invisibly** in the background (stealth mode):
```powershell
.\venv\Scripts\pythonw.exe main.py
```

## 🛡️ Security Invariants
This agent is built with local-first security as the primary engineering constraint:
*   **Owner-Only Middleware:** Drops all Telegram requests from unverified User IDs at the gateway level.
*   **Path Jail:** The `SmartFileResolver` restricts all file I/O strictly to `ALLOWED_DIRS` defined in your environment variables, preventing path traversal attacks.
*   **Deterministic Command Queue:** Bypasses LLM tool-calling state machines for compound commands (e.g., "start backend and expose port"), eliminating hallucination risks during multi-step executions.

## 🤝 Contributing
Contributions are welcome! Please ensure all pull requests pass the `pytest` regression suite before submission, especially regarding Permission Gate logic.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
