# 🌩️ Cloud Security Posture Management (CSPM) Tool – Python + Java Hybrid

## Overview
This project analyzes AWS cloud configurations for security misconfigurations using:
- **Python (Flask + Boto3)** for scanning and dashboard
- **Java** for compliance analysis
- **PostgreSQL** for storing user and scan history

## Setup
```bash
git clone https://github.com/<yourusername>/CSPM_Project.git
cd CSPM_Project
python -m venv venv
# Windows
.\venv\Scripts\Activate.ps1
# Linux/Mac
source venv/bin/activate
pip install -r backend/requirements.txt
```

### Database
```bash
sudo -u postgres psql
CREATE DATABASE cspm_db;
\i database/schema.sql
```

### Run Java Engine
```bash
cd java_engine
javac ComplianceEngine.java
java ComplianceEngine
```

### Run Flask App
```bash
cd backend
python app.py
```
Visit http://127.0.0.1:5000
