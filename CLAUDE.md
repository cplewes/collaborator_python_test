# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a simple Python test repository containing a single XMPP/BOSH client script that demonstrates authentication and messaging through Alberta Health Services infrastructure.

## Files Structure

- `collaborator_test.py` - Main Python script implementing XMPP/BOSH client functionality
- `reload.har` - HTTP Archive file (2MB+) containing network traffic data

## Development Environment

- **Python Version**: 3.12.3
- **Dependencies**: Uses standard library modules (`requests`, `xml.etree.ElementTree`, `base64`, `uuid`, `getpass`) plus system packages
- **Package Management**: No requirements.txt or pyproject.toml - dependencies managed at system level

## Running the Code

### Method 1: Password-based Authentication (Original)
```bash
python3 collaborator_test.py
```

The script prompts for:
- Username
- Password (hidden input)
- Target JID for message recipient
- Message content to send

### Method 2: Web-Client Style Authentication (Alternative)
```bash
python3 web_chat_auth.py
```

This alternative method prompts for:
- JWT token (extracted from web client URL)
- Target JID for message recipient
- Message content to send

## Code Architecture

### Password-based Authentication (collaborator_test.py)
The script follows a linear workflow:

1. **Authentication**: Authenticates with Keycloak using password grant flow
2. **BOSH Session**: Establishes XMPP-over-HTTP session with browser-like headers
3. **SASL Authentication**: Performs PLAIN SASL authentication using access token
4. **Stream Setup**: Restarts stream and binds resources
5. **Session Establishment**: Creates XMPP session
6. **Message Sending**: Sends chat message to target JID

### Web-Client Style Authentication (web_chat_auth.py)
Alternative approach mimicking the web client:

1. **JWT Token**: Uses pre-obtained JWT token from web client
2. **Pre-authenticated BOSH**: Establishes XMPP session without SASL authentication
3. **Resource Binding**: Binds resources and establishes session
4. **Message Sending**: Sends chat message to target JID

### Key Improvements
- **Enhanced Headers**: Both scripts now include browser-like headers for better compatibility
- **RID Management**: Proper request ID sequencing for BOSH protocol
- **Error Handling**: Detailed error messages for authentication and connection failures
- **Session Management**: Improved session tracking and connection management

Key configuration constants are defined at the top:
- BOSH_URL, CLIENT_ID, TARGET_IDP, REALM, KEYCLOAK_URL

## Troubleshooting

### Common Authentication Issues
- **401 Unauthorized on Keycloak**: Check username/password and ensure `targetIdp=LDAP1` is in the query string
- **SASL not-authorized**: Token may be expired or invalid - verify token format and expiration
- **BOSH connection failures**: Ensure proper headers are included, especially Origin and Referer
- **XML parsing errors**: Server may be returning HTML error pages instead of XML - check authentication

### Debug Tips
- Both scripts now include detailed error messages for different failure modes
- Check HTTP status codes and response content for authentication issues
- Verify that browser-like headers are properly set for BOSH requests
- Ensure RID (request ID) values are properly incremented

## Security Notes

This code contains hardcoded URLs pointing to Alberta Health Services infrastructure and handles authentication credentials. Any modifications should maintain security best practices for credential handling.