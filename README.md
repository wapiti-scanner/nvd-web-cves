# NVD Web CVEs

This project automates the process of downloading, processing, and generating short, compressed JSON files for specific software vulnerabilities from the National Vulnerability Database (NVD) GitHub mirror. Each JSON file contains CVEs (Common Vulnerabilities and Exposures) for various software, compressed using LZMA to save space.

## Table of Contents

- [NVD Web CVEs](#nvd-web-cves)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Software List](#software-list)
  - [Installation](#installation)
  - [Usage](#usage)
  - [License](#license)

## Features

- Downloads CVE data files from the NVD GitHub repository.
- Filters and extracts relevant CVE information based on specified software.
- Generates compressed JSON files for each software containing relevant CVE data.
- Automated daily updates using GitHub Actions.

## Software List

The project currently monitors the following software:

- Angular.js
- Apache HTTP Server
- Drupal
- jQuery
- IIS
- Jetty
- Joomla
- Next.js
- Node.js
- Nginx
- OpenSSL
- PHP
- PrestaShop
- SPIP
- Tomcat
- Underscore.js
- WebLogic
- WordPress

## Installation

### Prerequisites

- Python 3.10 or higher
- `pip` package manager

### Clone the Repository

```bash
git clone https://github.com/wapiti-scanner/nvd-web-cves.git
cd nvd-web-cves
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Running the Script

To download CVE data and generate JSON files, run:

```bash
python sync.py
```

This script performs the following steps:

1. Downloads the latest CVE data files from the NVD GitHub mirror.
2. Processes the downloaded files to extract relevant CVE information.
3. Generates compressed JSON files for each software in the releases directory.

### GitHub Actions

This project includes a GitHub Actions workflow to automate the process and create a new release with updated JSON files daily. The workflow file is located at `.github/workflows/make-realease.yml`.

### License

This project is licensed under the MIT License. See the LICENSE file for details.
