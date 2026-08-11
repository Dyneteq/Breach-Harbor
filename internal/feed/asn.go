package feed

// hostingASNs is a curated, static cross-reference of Autonomous System
// Numbers known to belong to cloud/hosting/datacenter operators — the
// operators whose IP space is virtually never a residential end user.
// It is intentionally not a live feed: unlike Spamhaus/FireHOL/Tor,
// there is no free, reliable, frequently-updated "is this ASN a
// datacenter" list to pull from, and ASN-to-operator mappings change
// slowly enough that a short, hand-maintained table is the honest
// tradeoff (PLAN.md M2: "internal/feed/asn.go, cross-referencing the
// IP's ASN ... against a curated hosting/cloud ASN list"). Extend this
// table as gaps are found; it is deliberately not exhaustive.
var hostingASNs = map[uint]string{
	16509:  "Amazon AWS",
	14618:  "Amazon AWS",
	8987:   "Amazon AWS (EU)",
	15169:  "Google Cloud",
	396982: "Google Cloud",
	8075:   "Microsoft Azure",
	8068:   "Microsoft",
	20940:  "Akamai (Linode)",
	63949:  "Akamai (Linode)",
	14061:  "DigitalOcean",
	62567:  "DigitalOcean",
	16276:  "OVH",
	24940:  "Hetzner Online",
	213230: "Hetzner Online",
	20473:  "Vultr (The Constant Company)",
	46606:  "Unified Layer",
	26496:  "GoDaddy",
	13335:  "Cloudflare",
	54113:  "Fastly",
	13238:  "Yandex Cloud",
	19551:  "Incapsula (Imperva)",
	135377: "UCloud",
	45102:  "Alibaba Cloud",
	37963:  "Alibaba Cloud",
	132203: "Tencent Cloud",
	136907: "Huawei Cloud",
	8560:   "IONOS",
	24961:  "Hetzner (myLoc)",
	36351:  "SoftLayer (IBM Cloud)",
	36352:  "ColoCrossing",
	53667:  "FranTech / BuyVM",
	40676:  "Psychz Networks",
	397423: "Contabo",
	51167:  "Contabo",
	9009:   "M247",
	60068:  "CDN77 (Datacamp)",
	31898:  "Oracle Cloud",
	31399:  "Linode",
}

// IsHostingASN reports whether asn is a known cloud/hosting/datacenter
// operator, and if so, its human-readable name.
func IsHostingASN(asn uint) (name string, ok bool) {
	name, ok = hostingASNs[asn]
	return name, ok
}
