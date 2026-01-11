# API Keys Configuration Guide

This project supports **multiple API keys** for both AbuseIPDB and VirusTotal to provide automatic fallback when one key fails or hits rate limits.

## Configuration

Create a `.env` file in the project root with your API keys:

### Single API Key (Backward Compatible)

```env
# AbuseIPDB
ABUSEIPDB_API_KEY=your_key_here

# VirusTotal
VIRUSTOTAL_API_KEY=your_key_here
```

### Multiple API Keys (Recommended)

You can configure up to 3 API keys for each service:

```env
# AbuseIPDB - Multiple Keys
ABUSEIPDB_API_KEY=your_first_key_here
ABUSEIPDB_API_KEY_2=your_second_key_here
ABUSEIPDB_API_KEY_3=your_third_key_here

# VirusTotal - Multiple Keys
VIRUSTOTAL_API_KEY=your_first_key_here
VIRUSTOTAL_API_KEY_2=your_second_key_here
VIRUSTOTAL_API_KEY_3=your_third_key_here
```

## How It Works

### Automatic Key Rotation

- **If a key fails** (rate limit, invalid key, authentication error), the system automatically tries the next key
- **Rate limiting**: Each key is tracked separately for rate limits
- **Fallback chain**: Keys are tried in order (1 → 2 → 3) until one succeeds or all fail

### When Keys Are Rotated

**AbuseIPDB:**
- HTTP 429 (Rate limit exceeded)
- HTTP 401/403 (Authentication failed)
- Request exceptions

**VirusTotal:**
- HTTP 429 (Rate limit exceeded)
- HTTP 204 (Rate limit exceeded)
- HTTP 401/403 (Authentication failed)
- Empty responses (for hashes)
- Invalid JSON responses
- Request exceptions

## Benefits

1. **Higher throughput**: With 3 keys, you can make up to 12 requests/minute to VirusTotal (4 per key)
2. **Resilience**: If one key fails, others continue working
3. **No downtime**: Automatic failover ensures continuous operation

## Getting API Keys

### AbuseIPDB
1. Sign up at https://www.abuseipdb.com/
2. Go to your account settings
3. Generate an API key
4. Free tier: 1,000 requests/day

### VirusTotal
1. Sign up at https://www.virustotal.com/
2. Go to your API key section
3. Copy your API key
4. Free tier: 4 requests/minute per key

## Security Note

⚠️ **Never commit your `.env` file to git!** It's already in `.gitignore` for your protection.

