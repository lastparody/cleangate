package util

import (
	"fmt"
	"os/exec"
	"strings"
)

// GetActiveNetworkService detects the primary network interface (e.g. "Wi-Fi")
func GetActiveNetworkService() (string, error) {
	// Get the default route interface
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "Wi-Fi", nil // Fallback
	}

	// Find the interface name (e.g. en0)
	var iface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			break
		}
	}
	if iface == "" {
		return "Wi-Fi", nil
	}

	// Map interface to network service name
	out2, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return "Wi-Fi", nil
	}

	lines := strings.Split(string(out2), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Device: "+iface) && i > 0 {
			serviceLine := lines[i-1]
			serviceName := strings.TrimPrefix(serviceLine, "Hardware Port: ")
			Debugf("Detected active network service: %s (interface: %s)", serviceName, iface)
			return serviceName, nil
		}
	}

	return "Wi-Fi", nil
}

// SetSystemProxy sets the macOS system HTTP and HTTPS proxy
func SetSystemProxy(addr string, port int) error {
	service, _ := GetActiveNetworkService()
	portStr := fmt.Sprintf("%d", port)

	cmds := [][]string{
		{"networksetup", "-setwebproxy", service, addr, portStr},
		{"networksetup", "-setsecurewebproxy", service, addr, portStr},
		{"networksetup", "-setwebproxystate", service, "on"},
		{"networksetup", "-setsecurewebproxystate", service, "on"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to run %v: %s (%w)", args, string(out), err)
		}
	}

	Debugf("System proxy set to %s:%d on service '%s'", addr, port, service)
	return nil
}

// UnsetSystemProxy disables the macOS system HTTP and HTTPS proxy
func UnsetSystemProxy() error {
	service, _ := GetActiveNetworkService()

	cmds := [][]string{
		{"networksetup", "-setwebproxystate", service, "off"},
		{"networksetup", "-setsecurewebproxystate", service, "off"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to run %v: %s (%w)", args, string(out), err)
		}
	}

	Debugf("System proxy disabled on service '%s'", service)
	return nil
}
