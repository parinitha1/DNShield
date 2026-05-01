# 🛡️ DNS Shield — Real-Time DNS Tunneling Detection System

> Passive network monitoring tool that detects and blocks DNS tunneling attacks using machine learning anomaly detection.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square&logo=fastapi)
![MongoDB](https://img.shields.io/badge/MongoDB-6.0+-darkgreen?style=flat-square&logo=mongodb)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-orange?style=flat-square&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)

---

## 📌 What is DNS Tunneling?

DNS tunneling is an attack technique that encodes arbitrary data (C2 traffic, file exfiltration payloads, VPN sessions) inside DNS queries and responses — exploiting the fact that port 53 is almost never blocked by firewalls.

**DNS Shield** detects this in real time by sniffing DNS traffic, extracting statistical features from each query, and using an Isolation Forest model to flag anomalous domains.

---

## ✨ Features

- 🔍 **Passive packet sniffing** on all network interfaces (UDP + TCP port 53)
- 🤖 **ML-based anomaly detection** using Isolation Forest (query length + Shannon entropy)
- 🚫 **Automatic domain blocking** — malicious domains are added to an in-memory block list instantly
- 🌐 **Source IP attribution** — identifies which host issued each DNS query
- 🗄️ **MongoDB persistence** — all events (Normal / Malicious / Blocked) are logged per session
- 📊 **Live dashboard** — real-time web UI with event table, stats, and filtering

---

## 🖥️ Dashboard Preview

The web dashboard auto-refreshes every 2 seconds and shows:

| Column | Description |
|--------|-------------|
| Timestamp | When the query was captured |
| Domain | The queried domain name |
| Source IP | IP of the machine that sent the query |
| Result | `Normal` / `Malicious` / `Blocked` |

Summary cards display total queries, malicious count, blocked count, and unique source IPs.

---

## 🏗️ Architecture

```
DNS Traffic (port 53)
        │
        ▼
┌──────────────────┐
│  Sniffer (Scapy) │  ← listens on all interfaces
└────────┬─────────┘
         │ domain + src_ip
         ▼
┌──────────────────────┐
│  Feature Extraction  │  ← query length + Shannon entropy
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  Isolation Forest    │  ← dns_model.pkl
└────────┬─────────────┘
         │
    ┌────┴────┐
    │         │
Malicious   Normal
    │         │
    ▼         ▼
┌─────────┐  ┌──────────┐
│ Blocker │  │  Log     │
└────┬────┘  └────┬─────┘
     │             │
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │   MongoDB   │
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │  Dashboard  │  → http://localhost:8000
     └─────────────┘
```

---

## 📁 Project Structure

```
dnstunnel/
├── backend/
│   ├── main.py          # FastAPI app + sniffer thread startup
│   ├── sniffer.py       # Scapy packet capture + processing
│   ├── detector.py      # Loads model, classifies domains
│   ├── features.py      # Length + Shannon entropy extraction
│   ├── blocker.py       # In-memory block list management
│   ├── database.py      # MongoDB insert + query helpers
│   ├── config.py        # MongoDB URI, DB name, model path
│   ├── models/
│   │   ├── train.py     # Isolation Forest training script
│   │   └── dns_model.pkl  # Pre-trained serialised model
│   └── utils/
│       ├── helpers.py
│       └── geoip.py     # GeoIP enrichment (optional)
├── frontend/
│   ├── index.html       # Live monitoring dashboard
│   ├── style.css        # Dark-theme styles
│   └── script.js        # Polling + table rendering
├── data/
│   └── sample_logs.json
└── requirements.txt
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10+
- MongoDB running on `localhost:27017`
- Root access or `CAP_NET_RAW` capability (required for raw packet capture)

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/dns-shield.git
cd dns-shield
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the model (optional — pre-trained model included)

```bash
python -m backend.models.train
```

### 4. Start the server

```bash
sudo uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

> **Why `sudo`?** Scapy needs raw socket access to capture packets at the network layer.

### 5. Open the dashboard

Navigate to [http://localhost:8000](http://localhost:8000) in your browser.

---

## 🧪 Testing with a DNS Tunnel

You can simulate an attack using [iodine](https://github.com/yarrick/iodine) from a Kali Linux machine:

```bash
# On the Kali attacker (replace with your tunnel domain and DNS server IP)
iodine -f -P yourpassword tunnel.yourdomain.com
```

DNS Shield will detect the high-entropy subdomain labels in real time and classify them as **Malicious**, then automatically block subsequent queries from the same domain.

---

## 🔬 How Detection Works

Each DNS query is reduced to two features:

| Feature | Why it matters |
|---------|----------------|
| **Query Length** | Tunneled queries embed encoded payloads in subdomains, producing labels >50 characters long. Legitimate hostnames are typically <40 characters. |
| **Shannon Entropy** | Encoded payloads (Base32/Base64/hex) have near-uniform character distributions (entropy ≈ 4.5–5.5 bits). Human-readable labels score much lower (≈ 2–3 bits). |

These two values are passed to an **Isolation Forest** model. Isolation Forest works by randomly partitioning the feature space — anomalous points (short path length to isolate) are flagged as outliers. A prediction of `-1` maps to **Malicious**; `1` maps to **Normal**.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Serves the live dashboard |
| `GET` | `/logs` | Returns all session log events as JSON |
| `GET` | `/blocked` | Returns the current block list |

### Example `/logs` response

```json
[
  {
    "domain": "ONXW2ZJAMFZA.tunnel.example.com",
    "result": "Malicious",
    "src_ip": "192.168.1.42",
    "timestamp": 1713200512.34
  },
  {
    "domain": "accounts.google.com",
    "result": "Normal",
    "src_ip": "192.168.1.10",
    "timestamp": 1713200514.89
  }
]
```

---

## ⚙️ Configuration

Edit `backend/config.py` to customise:

```python
MONGO_URI   = "mongodb://localhost:27017/"
DB_NAME     = "dns_detector"
COLLECTION  = "logs"
MODEL_PATH  = "backend/models/dns_model.pkl"
```

---

## 📦 Dependencies

```
scapy          # Packet capture and parsing
fastapi        # REST API framework
uvicorn        # ASGI server
pandas         # Data handling for model training
scikit-learn   # Isolation Forest implementation
joblib         # Model serialisation
pymongo        # MongoDB driver
geoip2         # (Optional) GeoIP enrichment
```

---

## ⚠️ Known Limitations

- **False positives** on high-entropy legitimate domains (e.g., CDN hostnames, DNSSEC zones)
- **Small training set** — the bundled model is trained on 9 synthetic examples; real-world deployment should retrain on representative traffic
- **Block list is in-memory** — restarting the server clears the block list
- **Queries only** — DNS responses are not currently analysed (large TXT records, NULL records)
- **Root required** — raw socket capture needs elevated privileges

---

## 🗺️ Roadmap

- [ ] Extended feature set: query rate per IP, subdomain depth, n-gram frequency
- [ ] Supervised model trained on a labelled DNS dataset (e.g., CIRA-CIC-DoHBrw-2020)
- [ ] GeoIP country + ASN enrichment on the dashboard
- [ ] Persistent block list with TTL expiry (Redis-backed)
- [ ] SIEM / webhook integration for alert forwarding
- [ ] Response-side analysis (TXT record size, TTL anomalies)

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — packet crafting and capture
- [FastAPI](https://fastapi.tiangolo.com/) — modern Python web framework
- [scikit-learn](https://scikit-learn.org/) — machine learning library
- Liu, Ting & Zhou (2008) — *Isolation Forest* algorithm
- Shannon (1948) — *A Mathematical Theory of Communication*
