<div align="center">
  <!-- Replace this link with your actual banner image link -->
  <img src="https://drive.google.com/file/d/1EyKfCvGymdxNniBL0Mjnr6MAsu47SlDU/view?usp=drivesdk" alt="PocketPC Agent Banner" width="100%">

  <h1>PocketPC Agent</h1>
  <p><b>An autonomous, zero-token Telegram agent for secure PC management, local dev environments, and anti-theft surveillance.</b></p>

  <!-- Add shields.io badges here -->
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
git clone [https://github.com/armansuri300105/Pocket_PC_Agent.git](https://github.com/armansuri300105/Pocket_PC_Agent.git)
cd Pocket_PC_Agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
