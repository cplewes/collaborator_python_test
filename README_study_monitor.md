# Study Monitor Proof-of-Concept

This script integrates XMPP message monitoring with Clario worklist patient lookup functionality.

## Overview

When someone shares a study via XMPP (using `https://share.study.link` URLs), the script:

1. **Detects** the study share URL in XMPP messages
2. **Extracts** the accession number from the procedure field (last word)
3. **Looks up** detailed patient information in Clario
4. **Outputs** structured JSON with patient details

## Features

- **Threaded Architecture**: Separate threads for XMPP polling and message processing
- **Dual Authentication**: Handles both XMPP (Keycloak) and Clario authentication
- **Async Integration**: Uses async/await for Clario API calls within threading
- **JSON Output**: Structured patient data (MRN, ULI, DOB, gender)
- **Error Handling**: Graceful handling of authentication and network failures

## Usage

```bash
python3 study_monitor_poc.py
```

The script will prompt for credentials:
- **XMPP Username/Password**: Your healthcare system XMPP credentials
- **Clario Username/Password**: Your Clario worklist credentials (password hidden)

## Example Output

When a study is shared, you'll see:

```json
{
  "timestamp": "2025-01-01T12:34:56.789",
  "accession": "AHS123456",
  "patient": {
    "mrn": "12345678",
    "uli": "external_id_123",
    "dob": "1990-01-01",
    "gender": "M"
  },
  "source": {
    "from_jid": "colleague@agfa.com",
    "study_url": "https://share.study.link?studyUID=...",
    "study_uid": "1.2.3.4.5.6.7.8.9",
    "procedure": "CT Chest with Contrast AHS123456"
  }
}
```

## Technical Details

### Threading Architecture
- **Main Thread**: Console input and monitoring
- **XMPP Polling Thread**: Continuous BOSH polling for messages
- **Message Processor Thread**: Processes messages and triggers Clario lookups

### Accession Extraction
The script extracts the accession number from the "procedure" field by taking the last word:
- `"CT Chest with Contrast AHS123456"` → `"AHS123456"`

### Clario Integration
- Uses hardcoded URL: `https://worklist.mic.ca`
- Async authentication and RPC-based search
- Maps Clario response fields to required output format

## Dependencies

- `requests` - XMPP BOSH communication
- `aiohttp` - Clario async HTTP client
- Standard library modules for threading, JSON, regex, etc.

## Error Handling

The script handles:
- Authentication failures (both XMPP and Clario)
- Network timeouts and connection errors
- Invalid study share URLs
- Missing accession numbers
- Clario search failures

## Security Notes

- Passwords are input using `getpass` (hidden from console)
- Uses existing healthcare authentication methods
- No credentials are stored or logged

## Stopping

Press `Ctrl+C` to gracefully stop all threads and close connections.