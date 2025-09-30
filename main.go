// Package mskeys provides utilities to scan the Windows registry for
// DigitalProductId values and decode Windows/Office product keys.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

var (
	flagOut   = flag.String("out", "", "Write output to text file")
	flagQuiet = flag.Bool("q", false, "Quiet mode (only keys)")
)

const keyChars = "BCDFGHJKMPQRTVWXY2346789"

// ProductKey represents a decoded product key with its registry location
type ProductKey struct {
	Path      string
	ValueName string
	Key       string
}

func main() {
	flag.Parse()

	keys, err := ScanForProductKeys()
	if err != nil {
		fmt.Printf("Error scanning for keys: %v\n", err)
		waitForUser()
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Println("No DigitalProductId values found in the scanned locations.")
		fmt.Println("This is normal for digitally-licensed systems.")
		waitForUser()
		return
	}

	output := formatOutput(keys, *flagQuiet)

	if *flagOut != "" {
		if err := writeToFile(*flagOut, output); err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			waitForUser()
			os.Exit(1)
		}
		fmt.Printf("Successfully wrote output to %s\n", *flagOut)
	} else {
		fmt.Print(output)
	}

	waitForUser()
}

// ScanForProductKeys scans common registry locations for product keys
func ScanForProductKeys() ([]ProductKey, error) {
	paths := []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion`,
		`SOFTWARE\Microsoft\Office\16.0\Registration`,
		`SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Registration`,
		`SOFTWARE\Microsoft\Office\15.0\Registration`,
		`SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Registration`,
		`SOFTWARE\Microsoft\Office\14.0\Registration`,
		`SOFTWARE\Wow6432Node\Microsoft\Office\14.0\Registration`,
	}

	var results []ProductKey

	for _, p := range paths {
		keys, _ := scanPath(registry.LOCAL_MACHINE, p)
		results = append(results, keys...)
	}

	// Check for OA3 key (digital license key stored as string)
	if key, err := readOA3Key(); err == nil && key != "" {
		results = append(results, ProductKey{
			Path:      `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
			ValueName: "OA3xOriginalProductKey",
			Key:       key,
		})
	}

	return results, nil
}

// DecodeDigitalProductId decodes a binary DigitalProductId to a product key string
func DecodeDigitalProductId(data []byte) string {
	if len(data) < 67 {
		return ""
	}

	// Extract key bytes (offset 52-66, 15 bytes total)
	segment := make([]byte, 15)
	copy(segment, data[52:67])

	decoded := decodeKeySegment(segment)
	if decoded != "" {
		return decoded
	}

	// If standard offset fails, scan for valid key
	for offset := 40; offset < len(data)-15; offset++ {
		seg := data[offset : offset+15]
		if key := decodeKeySegment(seg); key != "" {
			return key
		}
	}

	return ""
}

func scanPath(root registry.Key, path string) ([]ProductKey, error) {
	var results []ProductKey

	key, err := openRegistryKey(root, path)
	if err != nil {
		return results, err
	}
	defer key.Close()

	// Check current key
	if keys := scanKeyForDigitalProductId(key, path); len(keys) > 0 {
		results = append(results, keys...)
	}

	// Check all subkeys
	subKeys, _ := key.ReadSubKeyNames(-1)
	for _, subKey := range subKeys {
		fullPath := filepath.ToSlash(filepath.Join(path, subKey))
		k, err := openRegistryKey(root, fullPath)
		if err != nil {
			continue
		}

		if keys := scanKeyForDigitalProductId(k, fullPath); len(keys) > 0 {
			results = append(results, keys...)
		}
		k.Close()
	}

	return results, nil
}

func openRegistryKey(root registry.Key, path string) (registry.Key, error) {
	// Try standard access
	if k, err := registry.OpenKey(root, path, registry.READ); err == nil {
		return k, nil
	}

	// Try 64-bit view
	if k, err := registry.OpenKey(root, path, registry.READ|registry.WOW64_64KEY); err == nil {
		return k, nil
	}

	// Try 32-bit view
	return registry.OpenKey(root, path, registry.READ|registry.WOW64_32KEY)
}

func scanKeyForDigitalProductId(key registry.Key, path string) []ProductKey {
	var results []ProductKey

	values, err := key.ReadValueNames(-1)
	if err != nil {
		return results
	}

	for _, valueName := range values {
		if strings.ToLower(valueName) != "digitalproductid" {
			continue
		}

		data, _, err := key.GetBinaryValue(valueName)
		if err != nil || len(data) == 0 {
			continue
		}

		if productKey := DecodeDigitalProductId(data); productKey != "" {
			results = append(results, ProductKey{
				Path:      path,
				ValueName: valueName,
				Key:       productKey,
			})
		}
	}

	return results
}

func decodeKeySegment(segment []byte) string {
	if len(segment) != 15 {
		return ""
	}

	decoded := make([]byte, 0, 29)
	tmp := make([]byte, 15)
	copy(tmp, segment)

	// Decode using base-24 algorithm
	for i := 24; i >= 0; i-- {
		acc := 0
		for j := 14; j >= 0; j-- {
			acc = acc*256 + int(tmp[j])
			tmp[j] = byte(acc / 24)
			acc = acc % 24
		}

		decoded = append([]byte{keyChars[acc]}, decoded...)

		// Add hyphen every 5 characters (except at the end)
		if i%5 == 0 && i != 0 {
			decoded = append([]byte{'-'}, decoded...)
		}
	}

	if len(decoded) != 29 {
		return ""
	}

	return string(decoded)
}

func readOA3Key() (string, error) {
	path := `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	key, err := openRegistryKey(registry.LOCAL_MACHINE, path)
	if err != nil {
		return "", err
	}
	defer key.Close()

	value, _, err := key.GetStringValue("OA3xOriginalProductKey")
	if err != nil {
		return "", err
	}

	return value, nil
}

func formatOutput(keys []ProductKey, quietMode bool) string {
	var sb strings.Builder

	for _, k := range keys {
		if quietMode {
			sb.WriteString(k.Key)
			sb.WriteString("\n")
		} else {
			sb.WriteString(fmt.Sprintf("Path: %s\n", k.Path))
			sb.WriteString(fmt.Sprintf("Value: %s\n", k.ValueName))
			sb.WriteString(fmt.Sprintf("Key: %s\n\n", k.Key))
		}
	}

	return sb.String()
}

func writeToFile(filename string, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func waitForUser() {
	fmt.Print("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
