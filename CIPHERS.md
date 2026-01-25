# SSL/TLS Cipher Suite Guide

## Overview
SSL/TLS cipher enumeration and security assessment.

## Cipher Categories

### Recommended Ciphers
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_AES_128_GCM_SHA256
- ECDHE+AESGCM

### Deprecated Ciphers
- RC4 (broken)
- DES/3DES (weak)
- MD5-based MACs
- Export ciphers

### Vulnerable Ciphers
- NULL ciphers
- Anonymous key exchange
- EXPORT grade
- Static RSA

## Protocol Versions

### Secure
- TLS 1.3 (preferred)
- TLS 1.2 (acceptable)

### Insecure
- TLS 1.1 (deprecated)
- TLS 1.0 (deprecated)
- SSL 3.0 (broken)
- SSL 2.0 (broken)

## Enumeration Techniques

### Active Scanning
- Cipher probing
- Protocol negotiation
- Extension testing
- Certificate extraction

### Vulnerability Detection
- BEAST
- POODLE
- DROWN
- Heartbleed

## Configuration Assessment
- Perfect forward secrecy
- HSTS headers
- Certificate validity
- Chain verification

## Legal Notice
For authorized security assessments.
