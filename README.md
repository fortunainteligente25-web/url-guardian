#  URL-Guardian

A C++ based heuristic agent designed to detect potentially malicious and phishing-related URLs.

## Overview

URL Guardian analyzes URLs using a set of heuristic security rules. Each detected signal contributes to a risk score between 0 and 100, which is then used to classify the URL as:

- **SAFE**
- **SUSPICIOUS**
- **MALICIOUS**

The system also provides an explanation of the signals detected during the analysis, making the result more interpretable.

##  Detection Heuristics

URL Guardian currently checks for:

- IP addresses used as hosts
- User information (`@`) tricks
- Excessive subdomains
- Unusually long URLs
- Potentially risky top-level domains
- Sensitive keywords
- Potential brand impersonation
- Multiple hyphens in domains

##  Risk Scoring

| Score | Verdict |
|------:|---------|
| 0–29 | SAFE |
| 30–59 | SUSPICIOUS |
| 60–100 | MALICIOUS |

Each detected signal contributes a weighted score depending on its potential relevance.

##  Project Structure

```text
url-guardian/
├── include/
│   ├── heuristics.h
│   └── url_parser.h
│
├── src/
│   ├── heuristics.cpp
│   ├── main.cpp
│   └── url_parser.cpp
│
└── README.md
