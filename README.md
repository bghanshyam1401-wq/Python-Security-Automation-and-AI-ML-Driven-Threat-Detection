# Python-Security-Automation-and-AI-ML-Driven-Threat-Detection

# Python Security Automation and AI/ML Threat Detection

## Project Overview

This repository contains Python-based security automation tools designed to reduce security analyst workload. The project provides multithreaded network scanning, security-log parsing, public IP enrichment, VirusTotal intelligence lookups, and machine-learning-based threat detection.

The tools use authorized sample data and controlled lab systems. The port scanner uses Python's built-in socket and threading modules without Nmap, subprocess calls, or external scanner binaries.

## Repository Contents

- `port_scanner.py` - Multithreaded TCP port scanner with banner grabbing.
- `log_enricher.py` - Log parser and ip-api enrichment tool.
- `virustotal_check.py` - VirusTotal API v3 IP enrichment tool.
- `threat_detector.py` - Random Forest and Isolation Forest models.
- `sample_security.log` - Sample firewall and authentication logs.
- `dataset/Training Dataset.arff` - UCI Phishing Websites dataset.
- `model_results.txt` - Saved machine-learning results.
- `log_enricher_output.txt` - Saved ip-api sample output.
- `virustotal_output.txt` - Saved VirusTotal sample output.
- `requirements.txt` - Required Python packages.
- `.env.example` - Example environment-variable configuration.
- `.gitignore` - Excludes sensitive and temporary files.

## Requirements

- Python 3
- Internet access for REST API requests
- VirusTotal public API key
- Authorized system for port-scanner testing

Install the required packages:

```bash
pip3 install -r requirements.txt

If Kali Linux displays an externally managed environment error:

```bash
pip3 install -r requirements.txt --break-system-packages
```

## Environment Configuration

Create a local `.env` file:

```env
VT_API_KEY=your_actual_virustotal_api_key
```

The actual `.env` file is excluded by `.gitignore`.

The public `.env.example` file contains:

```env
VT_API_KEY=your_virustotal_api_key_here
```

---

## 1. Multithreaded Port Scanner

### Usage

```bash
python3 port_scanner.py 192.168.56.11 1 100
```

### Sample Output

```text
Port | State | Banner
------------------------------------------------------------
21   | Open | 220 (vsFTPd 2.3.4)
22   | Open | SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
23   | Open | No banner
25   | Open | No banner
53   | Open | No banner
80   | Open | No banner
```

---

## 2. Log Parser and IP Enrichment

### Usage

```bash
python3 log_enricher.py sample_security.log
```

### Sample Output

```json
{
    "1.1.1.1": {
        "country": "Australia",
        "isp": "Cloudflare, Inc",
        "hosting": true,
        "proxy": false,
        "mobile": false
    },
    "8.8.8.8": {
        "country": "United States",
        "isp": "Google LLC",
        "hosting": true,
        "proxy": false,
        "mobile": false
    }
}
```

---

## 3. Machine-Learning Threat Detector

### Dataset

The project uses the UCI Phishing Websites dataset.

Dataset statistics:

```text
Original Rows: 11055
Null Rows Removed: 0
Duplicate Rows Removed: 5206
Rows Remaining: 5849
```

### Class Distribution

Before preprocessing:

```text
1     6157
-1    4898
```

After preprocessing:

```text
-1    3019
1     2830
```

### Usage

```bash
python3 threat_detector.py
```

Save output:

```bash
python3 threat_detector.py | tee model_results.txt
```

### Model Results

```text
Random Forest Accuracy: 0.9462
Random Forest Precision: 0.9462
Random Forest Recall: 0.9462
Random Forest F1 Score: 0.9462

Isolation Forest Accuracy: 0.5309
Isolation Forest Precision: 0.5152
Isolation Forest Recall: 0.5152
Isolation Forest F1 Score: 0.5152
```

### Model Comparison

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
|---------|----------|----------|--------|----------|---------|
| Random Forest | 0.9462 | 0.9462 | 0.9462 | 0.9462 | Supervised classification |
| Isolation Forest | 0.5309 | 0.5152 | 0.5152 | 0.5152 | Unsupervised anomaly detection |

### Precision, Recall and F1 Discussion

Accuracy alone can be misleading for security datasets because a model may correctly classify many normal events while still missing important attacks. Precision measures how often malicious predictions are actually malicious. High precision reduces false positives and prevents analyst fatigue caused by excessive alerts. Recall measures how effectively a model identifies real attacks. High recall reduces false negatives and helps prevent malicious activity from being overlooked. The F1 score combines precision and recall into a single metric by calculating their harmonic mean. A higher F1 score indicates a balanced model that is effective at detecting threats while also minimizing incorrect alerts.

Random Forest relies on historical labelled data and may struggle when attackers introduce previously unseen techniques. Isolation Forest does not require labelled data but can classify unusual legitimate behaviour as an anomaly, increasing false positives in a real SOC environment.


---

## 4. VirusTotal REST API Enrichment

### Usage

```bash
python3 virustotal_check.py sample_security.log
```

### Example Output

```json
{
    "1.1.1.1": {
        "malicious": 0,
        "harmless": 57
    },
    "8.8.8.8": {
        "malicious": 0,
        "harmless": 54
    }
}
```

### Input → Process → Output Automation Mindset

Input → Process → Output is a simple automation approach used throughout this project.

- Input: Data supplied to the script such as IP addresses, port ranges, log files, datasets, or API keys.
- Process: Logic applied to the data such as scanning ports, extracting IPs using regular expressions, querying APIs, or running machine-learning models.
- Output: The final results shown to analysts such as open ports, threat-intelligence details, malicious detections, or threat classifications.

Mapping our tools:

| Script | Input | Process | Output |
|----------|----------|-----------|----------|
| port_scanner.py | Target IP and port range | Socket scanning and banner grabbing | Open ports and banners |
| log_enricher.py | Log file | Regex extraction and ip-api enrichment | Enriched public IP information |
| threat_detector.py | Phishing dataset | ML training and prediction | Threat classifications and evaluation metrics |

---

## SOAR Workflow Integration

A SOAR platform can integrate these tools into a single automated workflow. During data collection, `port_scanner.py` gathers information about exposed services running on a host. During enrichment, `log_enricher.py` extracts public IP addresses from logs and enriches them using external intelligence sources. `virustotal_check.py` adds threat-intelligence context by retrieving malicious and harmless vendor detections.

During detection, the machine-learning threat detector evaluates security observations and classifies them as malicious or benign. If the Random Forest model produces a confidence score greater than 90%, the SOAR platform can automatically block the related IP address at the firewall and create a high-priority incident. If the confidence score falls between 60% and 90%, the event should be escalated to a security analyst for manual investigation. Events below 60% should be monitored without an automated response.

These thresholds help balance false positives and false negatives. Excessive false positives can interrupt legitimate business activity, while false negatives may allow an attack to continue undetected. By combining automated enrichment, machine-learning analysis, and analyst review, the workflow provides rapid detection while preserving operational accuracy.

---

## Security Controls

- Thread locking prevents race conditions in the port scanner.
- All network operations use exception handling.
- Invalid and private IP addresses are excluded.
- API requests use timeouts.
- VirusTotal API keys are stored in environment variables.
- `.env` is excluded from GitHub.
- Duplicate records are removed before model training.
- Random Forest uses an 80/20 train-test split with `random_state=42`.

---

## Final Acceptance Checklist

- [x] Multithreaded port scanner implemented
- [x] Banner grabbing implemented
- [x] Graceful error handling implemented
- [x] Log parser created
- [x] Regex IPv4 extraction implemented
- [x] Private IP filtering implemented
- [x] ip-api enrichment implemented
- [x] VirusTotal integration implemented
- [x] Environment variable protection implemented
- [x] Random Forest model trained
- [x] Isolation Forest model trained
- [x] Accuracy, Precision, Recall and F1 Score reported
- [x] Model comparison provided
- [x] Input → Process → Output discussion included
- [x] SOAR workflow discussion included

## Ethical Use

This project is intended for authorized security testing, educational use, and controlled laboratory environments only.
