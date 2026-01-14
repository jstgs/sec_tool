# API Wrappers for Shodan & AbuseIPDB

A simple Python wrapper built around the Shodan and AbuseIPDB APIs for ease of use.

## Features

- **Shodan API Integration** - Look up IP addresses and retrieve host information
- **AbuseIPDB Integration** - Check IP reputation and abuse confidence scores
- **Type-safe Models** - Built with Pydantic for data validation and type safety

## Setup

1. Install dependencies:
```bash
pip install requests pydantic python-dotenv
```

2. Create a `.env` file with your API keys:
```env
SHODAN_KEY=your_shodan_api_key_here
ABUSE_KEY=your_abuseipdb_api_key_here
```


## Files

- `models.py` - Pydantic models for API responses
- `test.py` - API wrapper functions
- `.env` - Your API keys (not tracked in Git)
