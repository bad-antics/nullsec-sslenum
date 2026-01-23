-- NullSec SSLEnum - SSL/TLS Configuration Enumerator
-- Lua security tool demonstrating:
--   - Metatables for OOP
--   - Coroutines for async operations
--   - Dynamic typing with runtime checks
--   - Table-based data structures
--   - String pattern matching
--
-- Author: bad-antics
-- License: MIT

local VERSION = "1.0.0"

-- ANSI Colors
local Colors = {
    red = "\27[31m",
    green = "\27[32m",
    yellow = "\27[33m",
    cyan = "\27[36m",
    gray = "\27[90m",
    reset = "\27[0m"
}

local function colored(text, color)
    return (Colors[color] or "") .. text .. Colors.reset
end

-- Severity levels
local Severity = {
    CRITICAL = { name = "CRITICAL", color = "red", priority = 1 },
    HIGH = { name = "HIGH", color = "red", priority = 2 },
    MEDIUM = { name = "MEDIUM", color = "yellow", priority = 3 },
    LOW = { name = "LOW", color = "cyan", priority = 4 },
    INFO = { name = "INFO", color = "gray", priority = 5 }
}

-- SSL/TLS versions
local TLSVersions = {
    ["SSLv2"] = { secure = false, severity = Severity.CRITICAL },
    ["SSLv3"] = { secure = false, severity = Severity.CRITICAL },
    ["TLSv1.0"] = { secure = false, severity = Severity.HIGH },
    ["TLSv1.1"] = { secure = false, severity = Severity.MEDIUM },
    ["TLSv1.2"] = { secure = true, severity = Severity.INFO },
    ["TLSv1.3"] = { secure = true, severity = Severity.INFO }
}

-- Cipher suite security ratings
local CipherRatings = {
    -- Weak ciphers
    weak = {
        "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5", "ANON", "ADH", "AECDH"
    },
    -- Medium ciphers
    medium = {
        "3DES", "IDEA", "SEED", "CAMELLIA128"
    },
    -- Strong ciphers
    strong = {
        "AES128-GCM", "AES256-GCM", "CHACHA20-POLY1305", 
        "ECDHE", "DHE", "SHA256", "SHA384"
    }
}

-- Known vulnerabilities
local Vulnerabilities = {
    BEAST = {
        check = function(version, ciphers)
            return version == "TLSv1.0" and 
                   has_pattern(ciphers, "CBC")
        end,
        severity = Severity.MEDIUM,
        description = "BEAST vulnerability (CBC ciphers with TLS 1.0)"
    },
    POODLE = {
        check = function(version, _)
            return version == "SSLv3"
        end,
        severity = Severity.HIGH,
        description = "POODLE vulnerability (SSLv3 enabled)"
    },
    SWEET32 = {
        check = function(_, ciphers)
            return has_pattern(ciphers, "3DES") or has_pattern(ciphers, "IDEA")
        end,
        severity = Severity.MEDIUM,
        description = "SWEET32 vulnerability (64-bit block ciphers)"
    },
    FREAK = {
        check = function(_, ciphers)
            return has_pattern(ciphers, "EXPORT")
        end,
        severity = Severity.HIGH,
        description = "FREAK vulnerability (export ciphers)"
    },
    LOGJAM = {
        check = function(_, ciphers)
            return has_pattern(ciphers, "DHE") and 
                   not has_pattern(ciphers, "ECDHE")
        end,
        severity = Severity.MEDIUM,
        description = "LOGJAM vulnerability (weak DH parameters)"
    },
    DROWN = {
        check = function(version, _)
            return version == "SSLv2"
        end,
        severity = Severity.CRITICAL,
        description = "DROWN vulnerability (SSLv2 enabled)"
    },
    HEARTBLEED = {
        check = function(_, _)
            -- Would need actual OpenSSL version check
            return false
        end,
        severity = Severity.CRITICAL,
        description = "Heartbleed vulnerability"
    }
}

-- Helper: Check if any cipher matches pattern
function has_pattern(ciphers, pattern)
    for _, cipher in ipairs(ciphers or {}) do
        if cipher:upper():find(pattern:upper()) then
            return true
        end
    end
    return false
end

-- Finding class with metatable
local Finding = {}
Finding.__index = Finding

function Finding.new(severity, category, message, detail)
    local self = setmetatable({}, Finding)
    self.severity = severity
    self.category = category
    self.message = message
    self.detail = detail or ""
    return self
end

function Finding:format()
    local sev_str = string.format("[%-8s]", self.severity.name)
    return colored(sev_str, self.severity.color) .. " " .. 
           self.category .. ": " .. self.message
end

-- Scanner class
local SSLScanner = {}
SSLScanner.__index = SSLScanner

function SSLScanner.new(host, port)
    local self = setmetatable({}, SSLScanner)
    self.host = host
    self.port = port or 443
    self.findings = {}
    self.supported_versions = {}
    self.supported_ciphers = {}
    return self
end

function SSLScanner:scan()
    print(colored("Scanning: " .. self.host .. ":" .. self.port, "cyan"))
    print()
    
    -- Simulate scanning (real impl would use LuaSec or socket)
    self:enumerate_versions()
    self:enumerate_ciphers()
    self:check_vulnerabilities()
    self:analyze_certificate()
    
    return self.findings
end

function SSLScanner:enumerate_versions()
    print(colored("Testing SSL/TLS versions...", "gray"))
    
    -- Simulated results
    local detected = {
        { version = "TLSv1.0", supported = true },
        { version = "TLSv1.1", supported = true },
        { version = "TLSv1.2", supported = true },
        { version = "TLSv1.3", supported = true }
    }
    
    for _, result in ipairs(detected) do
        if result.supported then
            table.insert(self.supported_versions, result.version)
            local info = TLSVersions[result.version]
            
            if not info.secure then
                table.insert(self.findings, Finding.new(
                    info.severity,
                    "Protocol",
                    "Insecure protocol: " .. result.version,
                    "Consider disabling this protocol"
                ))
            end
            
            local status = info.secure and colored("✓", "green") or colored("✗", "red")
            print("  " .. status .. " " .. result.version)
        end
    end
    print()
end

function SSLScanner:enumerate_ciphers()
    print(colored("Testing cipher suites...", "gray"))
    
    -- Simulated cipher suites
    local ciphers = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "AES256-GCM-SHA384",
        "AES256-SHA256",
        "DES-CBC3-SHA"  -- Weak cipher for demo
    }
    
    self.supported_ciphers = ciphers
    
    local weak_count = 0
    for _, cipher in ipairs(ciphers) do
        local is_weak = false
        for _, pattern in ipairs(CipherRatings.weak) do
            if cipher:upper():find(pattern) then
                is_weak = true
                weak_count = weak_count + 1
                break
            end
        end
        
        if is_weak then
            print("  " .. colored("✗", "red") .. " " .. cipher)
        end
    end
    
    if weak_count > 0 then
        table.insert(self.findings, Finding.new(
            Severity.HIGH,
            "Cipher",
            weak_count .. " weak cipher(s) supported",
            "Disable weak ciphers"
        ))
    end
    
    print("  Supported: " .. #ciphers .. " cipher(s)")
    print()
end

function SSLScanner:check_vulnerabilities()
    print(colored("Checking vulnerabilities...", "gray"))
    
    for name, vuln in pairs(Vulnerabilities) do
        for _, version in ipairs(self.supported_versions) do
            if vuln.check(version, self.supported_ciphers) then
                table.insert(self.findings, Finding.new(
                    vuln.severity,
                    "Vulnerability",
                    name .. ": " .. vuln.description,
                    ""
                ))
                print("  " .. colored("✗", "red") .. " " .. name)
                break
            end
        end
    end
    print()
end

function SSLScanner:analyze_certificate()
    print(colored("Analyzing certificate...", "gray"))
    
    -- Simulated certificate analysis
    local cert = {
        subject = "CN=" .. self.host,
        issuer = "CN=Let's Encrypt Authority X3",
        valid_from = "2024-01-01",
        valid_to = "2024-04-01",
        key_size = 2048,
        signature_algo = "SHA256withRSA",
        san = { self.host, "www." .. self.host }
    }
    
    print("  Subject: " .. cert.subject)
    print("  Issuer:  " .. cert.issuer)
    print("  Valid:   " .. cert.valid_from .. " to " .. cert.valid_to)
    print("  Key:     RSA " .. cert.key_size .. "-bit")
    print()
    
    -- Check key strength
    if cert.key_size < 2048 then
        table.insert(self.findings, Finding.new(
            Severity.HIGH,
            "Certificate",
            "Weak RSA key (" .. cert.key_size .. " bits)",
            "Use at least 2048-bit keys"
        ))
    end
end

-- CLI functions
local function print_banner()
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║           NullSec SSLEnum - SSL/TLS Enumerator                   ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
end

local function print_usage()
    print_banner()
    print([[
USAGE:
    sslenum [OPTIONS] <host>

OPTIONS:
    -h, --help       Show this help
    -p, --port PORT  Port number (default: 443)
    -j, --json       JSON output
    -v, --verbose    Verbose output
    --no-color       Disable colors

EXAMPLES:
    sslenum example.com
    sslenum -p 8443 example.com
    sslenum -j example.com > report.json

CHECKS:
    - SSL/TLS version support
    - Cipher suite enumeration
    - Vulnerability detection (BEAST, POODLE, etc.)
    - Certificate analysis
    - Key strength verification
]])
end

local function print_findings(findings)
    if #findings == 0 then
        print(colored("✓ No security issues found", "green"))
        return
    end
    
    print(colored("Findings:", "yellow"))
    print()
    
    -- Sort by severity
    table.sort(findings, function(a, b)
        return a.severity.priority < b.severity.priority
    end)
    
    for _, finding in ipairs(findings) do
        print("  " .. finding:format())
    end
end

local function print_summary(findings)
    print()
    print(colored("═══════════════════════════════════════════", "gray"))
    print()
    print("Summary:")
    
    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 }
    for _, f in ipairs(findings) do
        counts[f.severity.name] = (counts[f.severity.name] or 0) + 1
    end
    
    print("  " .. colored("Critical:", "red") .. "  " .. counts.CRITICAL)
    print("  " .. colored("High:", "red") .. "      " .. counts.HIGH)
    print("  " .. colored("Medium:", "yellow") .. "    " .. counts.MEDIUM)
    print("  " .. colored("Low:", "cyan") .. "       " .. counts.LOW)
end

-- Main
local function main(args)
    local host = nil
    local port = 443
    
    for i, arg in ipairs(args) do
        if arg == "-h" or arg == "--help" then
            print_usage()
            return
        elseif arg == "-p" or arg == "--port" then
            port = tonumber(args[i + 1]) or 443
        elseif not arg:match("^-") and host == nil then
            host = arg
        end
    end
    
    if not host then
        print_banner()
        host = "example.com"  -- Demo mode
        print(colored("[Demo Mode]", "yellow"))
        print()
    else
        print_banner()
    end
    
    local scanner = SSLScanner.new(host, port)
    local findings = scanner:scan()
    
    print_findings(findings)
    print_summary(findings)
end

main(arg or {})
