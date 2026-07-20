package util

import (
	"encoding/json"
	"fmt"
)

type StartEvent struct {
	Event          string `json:"event"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	UpstreamProxy  string `json:"upstream_proxy"`
	SystemProxySet bool   `json:"system_proxy_set"`
}

type CertStatusEvent struct {
	Event   string `json:"event"`
	Status  string `json:"status"` // "installed", "already_exists", "failed"
	Message string `json:"message"`
}

type ListUpdateEvent struct {
	Event      string `json:"event"`
	Status     string `json:"status"` // "downloading", "success", "failed"
	TotalRules int    `json:"total_rules"`
}

type StopEvent struct {
	Event          string `json:"event"`
	CleanupSuccess bool   `json:"cleanup_success"`
}

func PrintJSON(v interface{}) {
	b, err := json.Marshal(v)
	if err == nil {
		fmt.Println(string(b))
	}
}

var DebugMode bool

// Debugf prints formatted logs only if DebugMode is true
func Debugf(format string, a ...interface{}) {
	if DebugMode {
		fmt.Printf("[DEBUG] "+format+"\n", a...)
	}
}
