# mskeys

A Windows utility to scan the registry for product keys (Windows and Microsoft Office) and decode them from DigitalProductId binary values.

## Why
Because I'm tired of Windows Defender constantly blocking the Produkey tool

## Features

- 🔍 Scans common registry locations for Windows and Office product keys
- 🔓 Decodes binary DigitalProductId values to readable product keys
- 📝 Supports output to text files
- 📦 Can be used as a CLI tool or imported as a Go package
- 🔐 Supports both legacy keys (DigitalProductId) and OA3 digital license keys

## Installation

### Pre-built Binary

Download the latest release from the releases page and run `mskeys.exe`.

### Build from Source

```bash
go build -o mskeys.exe mskeys.go
```

**Requirements:**
- Go 1.16 or later
- Windows OS
- `golang.org/x/sys/windows` package

## Usage

### As a CLI Tool

**Basic usage** (double-click or run from terminal):
```bash
mskeys.exe
```

Output:
```
Path: SOFTWARE\Microsoft\Windows NT\CurrentVersion
Value: DigitalProductId
Key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

Press Enter to exit...
```

**Save to file:**
```bash
mskeys.exe -out keys.txt
```

**Quiet mode** (keys only, no labels):
```bash
mskeys.exe -q
```

**Combine options:**
```bash
mskeys.exe -q -out keys.txt
```

### As a Go Package

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/keshon/mskeys"
)

func main() {
    // Scan for all product keys
    keys, err := mskeys.ScanForProductKeys()
    if err != nil {
        log.Fatal(err)
    }
    
    // Print found keys
    for _, key := range keys {
        fmt.Printf("Location: %s\n", key.Path)
        fmt.Printf("Product Key: %s\n\n", key.Key)
    }
}
```

**Decode a specific DigitalProductId:**
```go
package main

import (
    "fmt"
    
    "github.com/keshon/mskeys"
)

func main() {
    // Example: decode binary data from registry
    var binaryData []byte // ... get from registry
    
    productKey := mskeys.DecodeDigitalProductId(binaryData)
    if productKey != "" {
        fmt.Println("Decoded key:", productKey)
    }
}
```

## Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-out <file>` | Write output to specified text file | `-out keys.txt` |
| `-q` | Quiet mode - output keys only without labels | `-q` |

## How It Works

The tool scans the following registry locations:

### Windows Keys
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion`

### Office Keys (versions 2010, 2013, 2016+)
- `HKLM\SOFTWARE\Microsoft\Office\[14.0|15.0|16.0]\Registration\*`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\[14.0|15.0|16.0]\Registration\*`

### Decoding Process

1. Locates `DigitalProductId` binary values in the registry
2. Extracts the 15-byte key segment (typically at offset 52-66)
3. Decodes using base-24 algorithm with character set: `BCDFGHJKMPQRTVWXY2346789`
4. Formats as: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`

The tool also checks for OA3 digital license keys stored as plain strings.

## Product Key Types

### DigitalProductId (Binary)
Legacy format used by older Windows and Office versions. Stored as binary data and requires decoding.

### OA3xOriginalProductKey (String)
Modern digital license format. Already stored as a readable string in the registry.

## Important Notes

⚠️ **Legal Disclaimer**: This tool is for personal use only. Use it to recover your own legitimate product keys. Do not use it for software piracy or illegal activities.

⚠️ **Digital Licenses**: Modern Windows 10/11 systems often use digital licenses tied to your Microsoft account instead of traditional product keys. If no keys are found, this is normal and expected.

⚠️ **Administrator Rights**: Some registry locations may require administrator privileges to access.

## Troubleshooting

**No keys found:**
- Your system might use a digital license (Windows 10/11+)
- Try running as Administrator
- Keys might be in non-standard locations

**Access denied errors:**
- Run the executable as Administrator
- Check Windows permissions for registry access

**Build errors:**
- Ensure you have `golang.org/x/sys/windows` installed: `go get golang.org/x/sys/windows`
- This tool only works on Windows

## API Reference

### Types

```go
type ProductKey struct {
    Path      string  // Registry path where key was found
    ValueName string  // Registry value name
    Key       string  // Decoded product key
}
```

### Functions

```go
// ScanForProductKeys scans common registry locations for product keys
func ScanForProductKeys() ([]ProductKey, error)

// DecodeDigitalProductId decodes a binary DigitalProductId to a product key string
func DecodeDigitalProductId(data []byte) string
```

## License

MIT License - see LICENSE file for details

## Acknowledgments

Based on the Windows product key decoding algorithm used by various registry scanning tools.