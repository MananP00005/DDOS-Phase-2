# DDoS Attack — Simulation, Detection, Prevention & Deception

### Phase 2: ML-Based Defense System

> Implement a DDoS attack on a web server that incorporates an ML-based defense mechanism. Whenever a DDoS attack is detected, the ML model will identify and prevent it in real time, and attackers will be redirected to a deception system automatically — demonstrating both the attack vector and an automated, intelligent countermeasure.

---

## Table of Contents

- [Overview](#overview)
- [What Changed from Phase 1](#what-changed-from-phase-1)
- [Architecture](#architecture)
- [Three-Layer Defense](#three-layer-defense)
  - [Layer 1 — Detection (ML Classification)](#layer-1--detection-ml-classification)
  - [Layer 2 — Prevention (Sinkhole Isolation)](#layer-2--prevention-sinkhole-isolation)
  - [Layer 3 — Deception (Attacker Misdirection)](#layer-3--deception-attacker-misdirection)
- [Infrastructure](#infrastructure)
- [Repository Structure](#repository-structure)
- [Setup Guide](#setup-guide)
  - [1. Provision GCP VMs](#1-provision-gcp-vms)
  - [2. GCP Firewall Rules](#2-gcp-firewall-rules)
  - [3. Server VM Setup](#3-server-vm-setup)
  - [4. Botmaster VM Setup](#4-botmaster-vm-setup)
  - [5. Bot VM Setup](#5-bot-vm-setup)
  - [6. Legitimate Traffic VM Setup](#6-legitimate-traffic-vm-setup)
  - [7. ML Defense Setup](#7-ml-defense-setup)
- [Running the Lab](#running-the-lab)
- [Results](#results)
- [License](#license)

---

## Overview

Phase 2 builds on the [Phase 1 attack infrastructure](https://github.com/MananP00005/DDOS-Phase-1) by adding a **three-layer automated defense system**:

1. **Detection** — A Random Forest ML model trained on 14 traffic features classifies each source IP as attack or legitimate in real time, scanning nginx logs every 5 seconds.

2. **Prevention** — Detected attacker IPs are written to an nginx geo-map that routes their traffic to a **dedicated sinkhole container**, completely isolating them from the real Flask workers. Legitimate users experience zero impact.

3. **Deception** — The sinkhole returns convincing fake 503 responses with randomized delays (1.5–5s), fake server headers (`Apache/2.4.41`), and randomized body sizes. Attackers believe the server is overloaded and never learn they've been detected. Honeypot endpoints (`/admin`, `/wp-admin`, `/phpmyadmin`) capture vulnerability scanners.

**Key results:** 100% detection accuracy, 19,000+ bot requests intercepted, 0% false positive rate, 0 legitimate user failures.

---

## What Changed from Phase 1

| Component | Phase 1 | Phase 2 |
|-----------|---------|---------|
| Containers | 8 (Flask, nginx, monitoring) | **9** (+sinkhole container) |
| Defense | None — server goes down | ML detection + sinkhole isolation |
| nginx config | Basic rate limiting | geo-map sinkhole routing + honeypots |
| Flask app | Normal site only | Normal + sinkhole mode (dual-container) |
| Server headers | Real nginx/Python | **Fake Apache/PHP** headers |
| Honeypots | None | `/admin`, `/wp-admin`, `/phpmyadmin`, `/.env`, `/.git`, `/login` |
| ML model | Not implemented | Random Forest (14 features, 100% accuracy) |

---

## Architecture

```
                                    ┌───────────────────────────────────────────────┐
                                    │            ddos-server (us-central1-a)        │
                                    │                                               │
   ┌──────────┐                     │  ┌─────────────────────────────┐              │
   │ Bot-1    │──┐                  │  │          nginx :80          │              │
   │ us-c1-a  │  │                  │  │   ┌─────────────────────┐   │              │
   └──────────┘  │                  │  │   │  geo $sinkhole map  │   │              │
                 │                  │  │   │  (sinkholes.conf)   │   │              │
   ┌──────────┐  ├── HTTP :80 ────▶│  │   └────────┬────────────┘   │              │
   │ Bot-2    │──┤                  │  │            │                 │              │
   │ us-c1-b  │  │                  │  │    $sinkhole=0?    $sinkhole=1?            │
   └──────────┘  │                  │  │       │                │    │              │
                 │                  │  │       ▼                ▼    │              │
   ┌──────────┐  │                  │  │  ┌──────────┐  ┌───────────┐│              │
   │ Bot-3    │──┘                  │  │  │  Flask   │  │ Sinkhole  ││              │
   │ na-ne1-c │                     │  │  │ (real)   │  │ (fake 503)││              │
   └──────────┘                     │  │  │ 3 workers│  │ delays    ││              │
                                    │  │  └──────────┘  └───────────┘│              │
   ┌──────────────┐                 │  └─────────────────────────────┘              │
   │ Legit Traffic │── HTTP :80 ──▶│                                                │
   │ eu-north1-c   │                │  ┌──────────────────────┐                     │
   └──────────────┘                 │  │   detect.py daemon   │──── writes ────▶    │
                                    │  │   (ML inference)     │   sinkholes.conf    │
                                    │  │   scans every 5s     │   + nginx reload    │
                                    │  └──────────────────────┘                     │
                                    └───────────────────────────────────────────────┘
```

**Traffic flow after detection:**
- **Clean IP** → nginx → Flask (real site) → **200 OK**
- **Flagged IP** → nginx → Sinkhole container → **fake 503** (1.5–5s delay)
- **Scanner hitting /admin** → nginx honeypot → **fake login page** (logged)

---

## Three-Layer Defense

### Layer 1 — Detection (ML Classification)

The `detect.py` daemon tails the nginx access log every 5 seconds, extracts 14 features per source IP over a 10-second sliding window, and scores each IP using the trained Random Forest model.

**14 Features extracted per IP per window:**

| Feature | Description | Attack Value | Legit Value |
|---------|-------------|-------------|-------------|
| `req_rate` | Requests per second | ~100–4800/s | ~0.1–2/s |
| `inter_mean` | Mean inter-arrival time | ~0.001s | ~0.5–2s |
| `inter_std` | Std deviation of timing | ~0 (robotic) | ~0.3–1s |
| `unique_urls` | Distinct URLs requested | 1 (`/heavy` only) | 5–20 |
| `url_entropy` | URL pattern randomness | ~0 | ~2–4 |
| `pct_heavy` | % requests to `/heavy` | ~1.0 | ~0 |
| `pct_5xx` | % 5xx responses | ~0.3–1.0 | ~0 |
| `pct_200` | % 200 responses | ~0–0.7 | ~0.95 |
| `ua_entropy` | User-agent diversity | ~0 | ~0.5–1.5 |
| `pct_ab` | % ApacheBench UA | ~1.0 | ~0 |
| `pct_ddosbot` | % DDoS-Bot UA | ~0–1.0 | ~0 |
| `dur_mean` | Mean response time | ~1.5–5s | ~0.1–0.5s |
| `dur_std` | Response time variance | High | Low |
| `bytes_mean` | Mean response size | ~73 bytes | ~5000–17000 |

**Model performance:**

| Metric | Random Forest | XGBoost |
|--------|--------------|---------|
| Accuracy | 100.00% | 99.80% |
| F1 Score | 1.0000 | 0.9980 |
| False Positive Rate | 0.00% | 0.20% |
| CV F1 (5-fold) | 1.0000 | 0.9975 |
| **Winner** | **YES** | No |

**Top 3 most important features:** `pct_ab` (0.27), `pct_heavy` (0.21), `inter_mean` (0.15)

### Layer 2 — Prevention (Sinkhole Isolation)

When `detect.py` flags an IP (probability ≥ 0.60):

1. Writes `<IP> 1;` to `sinkholes.conf`
2. Reloads nginx (`docker exec ddos-nginx nginx -s reload`)
3. nginx geo-map routes all future requests from that IP to the sinkhole upstream
4. The sinkhole container (`SINKHOLE_MODE=true`) handles those requests with its own independent Gunicorn workers
5. Real Flask workers are **never touched** by bot traffic after detection

**Why a separate container?** Initially the sinkhole was an endpoint inside the real Flask app. The problem: the sinkhole's deliberate 1.5–5s delays consumed the same Gunicorn workers as the real site, still causing denial of service. The final design uses a completely separate Docker container with its own worker pool, achieving total isolation.

### Layer 3 — Deception (Attacker Misdirection)

**Sinkhole responses are engineered to be indistinguishable from a genuinely overloaded server:**
- HTTP 503 status (same as real overload)
- Randomized delay of 1.5–5.0 seconds (real overloaded servers don't respond instantly)
- Randomized body padding (identical response sizes would be a tell)
- `Retry-After` header with random value (mimics real server behavior)

**Honeypot endpoints catch vulnerability scanners:**

| Path | Response | Purpose |
|------|----------|---------|
| `/admin`, `/wp-admin`, `/phpmyadmin` | Fake admin login form | Catches CMS/DB scanners |
| `/.env`, `/.git` | Fake login form | Catches environment/source scrapers |
| `/login` | Fake university portal form | Catches credential stuffers |

All honeypot hits are logged to a separate `honeypot.log` with `[HONEYPOT]` tags.

**Server identity spoofing:**

| Header | Fake Value | Real Value |
|--------|-----------|------------|
| `Server` | `Apache/2.4.41 (Ubuntu)` | `nginx/1.25` |
| `X-Powered-By` | `PHP/7.4.3` | `Python/Flask` |

Attackers send Apache/PHP-specific exploits that miss entirely.

---

## Infrastructure

### GCP Virtual Machines

| VM Name | Role | Machine Type | vCPU | RAM | Disk | Zone |
|---------|------|-------------|------|-----|------|------|
| `ddos-server` | Target + Defense | e2-custom-4-8192 | 4 | 8 GB | 50 GB SSD | us-central1-a |
| `ddos-botmaster` | Attack orchestrator | e2-medium | 2 | 4 GB | 10 GB | us-central1-b |
| `ddos-bot-1` | Attack bot | e2-micro | 0.25 | 1 GB | 10 GB | us-central1-a |
| `ddos-bot-2` | Attack bot | e2-micro | 0.25 | 1 GB | 10 GB | us-central1-b |
| `ddos-bot-3` | Attack bot | e2-micro | 0.25 | 1 GB | 10 GB | northamerica-northeast1-c |
| `legittraffic` | Simulated students | e2-micro | 0.25 | 1 GB | 10 GB | europe-north1-c |

### Docker Container Stack (9 containers)

| Container | Port | Role | New in Phase 2 |
|-----------|------|------|----------------|
| `ddos-flask` | 5000 (internal) | Real web app — 3 sync workers | No |
| `ddos-sinkhole` | 5000 (internal) | Deception container — fake 503s to flagged IPs | **YES** |
| `ddos-nginx` | 80 (public) | Reverse proxy + geo-map routing + honeypots | Updated |
| `ddos-grafana` | 3000 | Monitoring dashboard | No |
| `ddos-prometheus` | 9090 | Metrics collection | No |
| `ddos-loki` | 3100 | Log aggregation | No |
| `ddos-promtail` | Internal | Log shipping | No |
| `ddos-node-exporter` | Internal | Host OS metrics | No |
| `ddos-nginx-exporter` | Internal | nginx metrics | No |

---

## Repository Structure

```
.
├── README.md
├── .gitignore
├── server/                              # Server VM — Docker stack
│   ├── docker-compose.yml               # 9-container stack (includes sinkhole)
│   ├── flask_app/
│   │   ├── Dockerfile
│   │   ├── app.py                       # Dual-mode: normal site + sinkhole mode
│   │   ├── requirements.txt
│   │   └── templates/                   # Westbrook University website
│   ├── nginx/
│   │   ├── nginx.conf                   # geo-map routing + honeypots + fake headers
│   │   └── sinkholes.conf               # ML-populated IP sinkhole list
│   ├── prometheus/
│   │   └── prometheus.yml
│   ├── promtail/
│   │   └── promtail.yml
│   ├── grafana/
│   │   └── provisioning/
│   ├── defense/cache/
│   │   ├── blocked_ips.conf
│   │   └── ip_cache.json
│   ├── website/                         # Static HTML fallbacks
│   └── logs/                            # nginx logs (gitignored)
├── defense/                             # ML Defense System
│   ├── scripts/
│   │   ├── train_pipeline.py            # Feature extraction + SMOTE + RF/XGB training
│   │   └── detect.py                    # Real-time detection daemon
│   ├── models/
│   │   ├── best_model.pkl               # Trained Random Forest model
│   │   ├── scaler.pkl                   # StandardScaler for feature normalization
│   │   ├── model_meta.json              # Model metadata + feature importance
│   │   └── comparison.json              # RF vs XGBoost comparison
│   ├── requirements.txt                 # Python ML dependencies
│   └── data/                            # Training data output (gitignored)
├── botmaster/
│   └── attack.sh                        # Three-phase attack script
└── legittraffic/
    └── traffic_gen.py                   # Realistic student browsing simulator
```

---

## Setup Guide

### 1. Provision GCP VMs

Create 6 VMs in the Google Cloud Console (**Compute Engine → VM instances → Create Instance**) with the specs listed in the [Infrastructure](#infrastructure) table.

**Server VM (`ddos-server`):**
- **Image:** Ubuntu 22.04 LTS
- **Machine type:** e2-custom (4 vCPU, 8 GB memory)
- **Boot disk:** 50 GB SSD
- **Zone:** us-central1-a
- **Firewall:** Check ✅ *Allow HTTP traffic* and ✅ *Allow HTTPS traffic*
- **Networking → External IPv4 address:** Reserve a static external IP

**Botmaster VM (`ddos-botmaster`):** e2-medium (2 vCPU, 4 GB), 10 GB disk, us-central1-b

**Bot VMs (`ddos-bot-1/2/3`):** e2-micro, 10 GB disk, distributed across zones

**Legitimate Traffic VM (`legittraffic`):** e2-micro, 10 GB disk, europe-north1-c

### 2. GCP Firewall Rules

Navigate to **VPC Network → Firewall → Create Firewall Rule**:

**Rule 1 — `allow-internal-ssh`**
```
Direction:        Ingress
Targets:          Specified target tags → ddos-bot
Source filters:   IP ranges → 0.0.0.0/0
Protocols/ports:  tcp:22
Priority:         1000
```

**Rule 2 — `allow-server-ports`**
```
Direction:        Ingress
Targets:          Specified target tags → ddos-server
Source filters:   IP ranges → 0.0.0.0/0
Protocols/ports:  tcp:80, 443, 3000, 3100, 6443, 9080, 9090
Priority:         1000
```

**Rule 3 — `default-allow-http`**
```
Direction:        Ingress
Targets:          Specified target tags → http-server
Source filters:   IP ranges → 0.0.0.0/0
Protocols/ports:  tcp:80
Priority:         1000
```

### 3. Server VM Setup

SSH into `ddos-server`:

```bash
# ── Update system ──
sudo apt update && sudo apt upgrade -y

# ── Install Docker Engine ──
sudo apt install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER

# ── Install Python + ML dependencies (for detect.py) ──
sudo apt install -y python3 python3-pip htop net-tools curl jq tree git
pip3 install -r defense/requirements.txt --break-system-packages

# ── Install utilities ──
sudo apt install -y htop net-tools curl jq tree git
```

> Log out and SSH back in for the docker group to take effect.

```bash
git clone <repo-url> ddos-lab
cd ddos-lab/server

# Build and start all 9 containers
docker compose up -d --build

# Verify — should see 9 containers including ddos-sinkhole
docker ps
```

### 4. Botmaster VM Setup

SSH into `ddos-botmaster`:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y openssh-client apache2-utils htop net-tools curl git

# Generate SSH key pair for bot communication
ssh-keygen -t ed25519 -f ~/.ssh/botkey -N "" -C "ddos-botmaster"

# Display the public key — you'll paste this into each bot VM
cat ~/.ssh/botkey.pub
```

### 5. Bot VM Setup

SSH into **each** bot VM (`ddos-bot-1`, `ddos-bot-2`, `ddos-bot-3`):

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2-utils curl
```

Then authorize the botmaster's SSH key on each bot:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys
# Paste the entire public key from botmaster's ~/.ssh/botkey.pub
chmod 600 ~/.ssh/authorized_keys
```

Repeat on all three bot VMs. Verify from the botmaster:

```bash
ssh -i ~/.ssh/botkey -o StrictHostKeyChecking=no <BOT1_INTERNAL_IP> 'hostname'
ssh -i ~/.ssh/botkey -o StrictHostKeyChecking=no <BOT2_INTERNAL_IP> 'hostname'
ssh -i ~/.ssh/botkey -o StrictHostKeyChecking=no <BOT3_INTERNAL_IP> 'hostname'
```

### 6. Legitimate Traffic VM Setup

SSH into `legittraffic`:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip curl
pip3 install requests --break-system-packages
```

### 7. ML Defense Setup

On the **server VM**, after the Docker stack is running:

**Step 1 — Update paths in the scripts:**

Edit `defense/scripts/detect.py` and `defense/scripts/train_pipeline.py` — replace `<YOUR_USER>` with your actual Linux username, and `<LEGIT_TRAFFIC_EXTERNAL_IP>` with the external IP of your `legittraffic` VM.

**Step 2 — Generate training data (requires Phase 1 attack logs):**

Run at least one attack cycle first to generate nginx access logs with both attack and legitimate traffic, then:

```bash
python3 defense/scripts/train_pipeline.py
```

This parses the logs, auto-labels IPs (ApacheBench → attack, Mozilla → legit), extracts features, applies SMOTE balancing, trains Random Forest + XGBoost, and saves the best model to `defense/models/`.

**Step 3 — Start the detection daemon:**

```bash
python3 defense/scripts/detect.py
```

The daemon tails the nginx access log, scores each IP every 5 seconds, and automatically sinkhole-routes detected attackers via nginx reload.

> **Note:** The pre-trained model (`defense/models/best_model.pkl`) is included in this repo. You can skip Step 2 and go straight to Step 3 if your attack setup matches the original (ApacheBench bots targeting `/heavy`).

---

## Running the Lab

**1. Start the server** (on `ddos-server`):
```bash
cd ddos-lab/server
docker compose up -d --build
docker ps  # Verify 9 containers
```

**2. Start legitimate traffic** (on `legittraffic`):
```bash
python3 legittraffic/traffic_gen.py
```

**3. Start the ML defense** (on `ddos-server`, separate terminal):
```bash
python3 defense/scripts/detect.py
```

**4. Launch the attack** (on `ddos-botmaster`):
```bash
chmod +x botmaster/attack.sh
./botmaster/attack.sh
```

**5. Watch the defense in action:**
- `detect.py` terminal shows `[SINKHOLED]` for each bot IP as it's flagged
- Legitimate traffic continues showing `✅ 200` responses
- Grafana dashboard at `http://<SERVER_IP>:3000` (admin / ddoslab123) shows the full cycle

**6. Stop the attack:** Press `Ctrl+C` on the botmaster.

---

## Results

| Phase | Concurrent Reqs | Server Behavior | Legit User Experience | Defense State |
|-------|----------------|-----------------|----------------------|---------------|
| Pre-attack | 0 | Normal | 200 OK, <100ms | Monitoring only |
| Phase 1 (0–30s) | 9 | Workers available | 200 OK, normal | ML watching |
| Phase 2 (30–60s) | 30 | Queue filling | Slight slowdown | ML flagging begins |
| Phase 3 start | 300 | Workers saturated | 503 briefly | ML flags all bot IPs |
| **After detection** | **300 ongoing** | **Bots in sinkhole** | **200 OK restored** | **Full defense active** |
| Attack stopped | 0 | Immediate recovery | 200 OK, <100ms | Sinkholes remain |

| Metric | Value |
|--------|-------|
| Detection accuracy | 100% (prob=0.998–1.000) |
| Time to first detection | 5–10 seconds |
| False positive rate | 0% |
| Bot requests intercepted | 19,000+ |
| Legitimate user failures after defense | 0 |
| Sinkhole response | Fake 503, 1.5–5s delay |
| Honeypot scanner captures | Multiple real scanners |

---

## License

> **Disclaimer:** This lab is designed for controlled educational environments. Running DDoS attacks against systems you do not own or have explicit permission to test is illegal. All attacks in this project target infrastructure provisioned and controlled by the project author on GCP.
