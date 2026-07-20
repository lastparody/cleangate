package engine

import "strings"

// ListRegistry holds the comprehensive catalog of popular adblock and privacy lists.
var ListRegistry = map[string]string{
	// 1. Reklam Engelleme (Ana Listeler)
	"easylist":   "https://easylist.to/easylist/easylist.txt",
	"adguard":    "https://filters.adtidy.org/extension/chromium/filters/2.txt", // AdGuard Base
	"ublock":     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
	"peterlowe":  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",

	// 2. Gizlilik / İzleyici (Tracker)
	"easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
	"adguard-trk": "https://filters.adtidy.org/extension/chromium/filters/3.txt", // AdGuard Tracking Protection

	// 3. Kötü Amaçlı Yazılım / Crypto
	"nocoin":      "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
	"adguard-mal": "https://filters.adtidy.org/extension/chromium/filters/9.txt", // AdGuard URLhaus / Malware

	// 4. Rahatsızlık Verici İçerik (Annoyances & Cookies)
	"fanboy-annoy": "https://easylist.to/easylist/fanboy-annoyance.txt",
	"fanboy-social": "https://easylist.to/easylist/fanboy-social.txt",
	"easylist-cookie": "https://easylist.to/easylist/easylist-cookie.txt",
	"idcac":        "https://www.i-dont-care-about-cookies.eu/abp/", // I don't care about cookies
	"adguard-annoy": "https://filters.adtidy.org/extension/chromium/filters/14.txt",

	// 5. DNS/Hosts Tabanlı Listeler
	"stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"adaway":      "https://adaway.org/hosts.txt",
}

// GetListURLs converts a comma-separated string of IDs into actual URLs.
// If "all" is provided, it returns all lists.
// If an ID is not found, it assumes the ID is a direct URL.
func GetListURLs(ids string) []string {
	if ids == "all" {
		var urls []string
		for _, url := range ListRegistry {
			urls = append(urls, url)
		}
		return urls
	}

	var urls []string
	parts := strings.Split(ids, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if url, exists := ListRegistry[part]; exists {
			urls = append(urls, url)
		} else {
			// If it's not a known ID, assume it's a custom URL passed by the user
			if strings.HasPrefix(part, "http") {
				urls = append(urls, part)
			}
		}
	}
	return urls
}
