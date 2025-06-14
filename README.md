# Network Debug Tool

This is a layer-by-layer Windows network diagnostic tool based on the OSI model. It tests each layer and logs results with explanations to a timestamped log file.

## Features

- Physical to Application layer diagnostics
- Automatically detects default gateway
- Warns on high latency
- Creates a detailed log per run

## Installation

```bash
pip install -r requirements.txt
python network_tester.py
```

## Usage

Run the script and follow the on-screen prompts. A timestamped log is saved to `network_diagnostic_log.txt` for later review.
