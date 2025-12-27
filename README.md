# F5 BIG-IP Configuration Review Tool (LTM + ASM)

This repository contains two report generators:

- LTM report generator: pulls data from F5 iHealth QKView Analyzer API using a qkview_id and produces a Word report. 
- ASM report generator: reads ASM policy JSON files from a local `./policies` folder and produces one Word report per policy. 

All Reports are saved under a local `./reports` directory. 

## What you get

### LTM report
Generates an LTM configuration review report from a given `QKView ID.`
Uses iHealth endpoints for commands/diagnostics/files. 

### ASM report
Scans `./policies/*.json` and creates a report per ASM policy. 


## Prerequisites

Python 3.10+ recommended

Dependencies:
- python-docx (Word report generation)
- requests (used by the LTM tool to call iHealth APIs)
- openpyxl (used for Excel workbook creation)

## Installation process


1. Clone the repo to your PC

```
git clone https://github.com/skenderidis/bigip-audit
```

2. Using a virtual environment is strongly recommended.
```
python3 -m venv .venv
source .venv/bin/activate
```

3. After activating the virtual environment, install dependencies:
```
pip install -r requirements.txt
```
4. Ready to create your LTM/ASM report.

## How to use the tool

### LTM report
1. For the LTM report you will need valid F5 iHealth API credentials (**CLIENT_ID** and **CLIENT_SECRET**). These can be acquired from (https://ihealth.f5.com/qkview-analyzer/settings) under the `API Token` Section. 
The tool supports **two ways** of providing F5 iHealth API credentials:

- **Environment variables** (recommended)
- **Command-line arguments**

> Using Environment Variables is the recommended way, because this approach avoids exposing credentials in shell history or scripts.

```bash
export CLIENT_ID="your_client_id_here"
export CLIENT_SECRET="your_client_secret_here"
```

2. Once you have the credentials you can run the **create_ltm.py** script to create the LTM report.

```bash
python create_ltm.py \
  --customer "ACME Bank" \
  --qkview_id "123456"
```

Alternatively you can add your credentials on the CLI like the following example:
```bash
python create_ltm.py \
  --customer "ACME Bank" \
  --qkview_id "123456" \
  --client_id "your_client_id_here" \
  --client_secret "your_client_secret_here"
  ```

### ASM report

1. One or more ASM policy JSON files placed in the **policies/** directory. 

> **IMPORTANT**
> 
> The policies needs to be exported from ASM in `FULL` and NOT in `TEMPLATE` mode. 

2. run the Python script, providing the customer name

```bash
python create_asm.py --customer "ACME Bank"
```

## Support

For support, please open a GitHub issue.  Note, the code in this repository is community supported and is not supported by F5 Networks.  For a complete list of supported projects please reference [SUPPORT.md](SUPPORT.md).

