package micetro

import (
	"sort"
	"strings"
)

// FindBestZoneForFQDN returns the zone (e.g., example.com) and relative name.
func FindBestZoneForFQDN(c *Client, fqdn string) (zone, rel string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zones, err := c.listZones()
	if err == nil && len(zones) > 0 {
		sort.SliceStable(zones, func(i, j int) bool {
			return len(zones[i]) > len(zones[j])
		})
		for _, z := range zones {
			if strings.HasSuffix(fqdn, z) {
				rel = strings.TrimSuffix(fqdn, "."+z)
				if rel == "" {
					rel = "@"
				}
				return z, rel
			}
		}
	}
	return "", ""
}
