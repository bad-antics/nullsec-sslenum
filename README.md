# NullSec SSLEnum

Lua SSL/TLS configuration enumerator demonstrating metatables and coroutines.

## Features

- **Metatables** - OOP-style class system
- **Coroutines** - Async operation support
- **Pattern Matching** - String-based cipher analysis
- **Dynamic Typing** - Flexible data structures
- **Table Structures** - Configuration management

## Checks

| Category | Description |
|----------|-------------|
| Protocols | SSLv2/v3, TLS 1.0-1.3 |
| Ciphers | Weak, medium, strong |
| Vulnerabilities | BEAST, POODLE, SWEET32, etc. |
| Certificate | Key size, expiry, SAN |

## Vulnerabilities Detected

| Name | Severity | Condition |
|------|----------|-----------|
| DROWN | Critical | SSLv2 enabled |
| POODLE | High | SSLv3 enabled |
| FREAK | High | Export ciphers |
| BEAST | Medium | CBC with TLS 1.0 |
| SWEET32 | Medium | 64-bit block ciphers |
| LOGJAM | Medium | Weak DH params |

## Run

```bash
# With Lua
lua sslenum.lua example.com

# With LuaJIT (faster)
luajit sslenum.lua example.com

# Custom port
lua sslenum.lua -p 8443 example.com
```

## Usage

```bash
# Basic scan
./sslenum.lua example.com

# Specify port
./sslenum.lua -p 8443 example.com

# JSON output
./sslenum.lua -j example.com > report.json

# Verbose
./sslenum.lua -v example.com
```

## Output Example

```
Testing SSL/TLS versions...
  ✗ TLSv1.0
  ✗ TLSv1.1
  ✓ TLSv1.2
  ✓ TLSv1.3

Checking vulnerabilities...
  ✗ BEAST

Findings:
  [HIGH]     Protocol: Insecure protocol: TLSv1.0
  [MEDIUM]   Vulnerability: BEAST
```

## Author

bad-antics | [X/Twitter](https://x.com/AnonAntics)

## License

MIT
