package intel

import "strings"

// Source describes an external search or intelligence source the AI can suggest.
type Source struct {
	Name     string
	Domain   string
	Category string
	UseCase  string
}

var RecommendedSources = []Source{
	{Name: "Shodan", Domain: "shodan.io", Category: "Server", UseCase: "internet-exposed hosts, banners, ports, and service fingerprints"},
	{Name: "Google", Domain: "google.com", Category: "Dorks", UseCase: "broad web discovery, indexed exposure checks, and targeted dorking"},
	{Name: "WiGLE", Domain: "wigle.net", Category: "WiFi Networks", UseCase: "wireless network intelligence and geolocation research"},
	{Name: "grep.app", Domain: "grep.app", Category: "Code Search", UseCase: "public code search for secrets, endpoints, and implementation clues"},
	{Name: "BinaryEdge App", Domain: "app.binaryedge.io", Category: "Threat Intelligence", UseCase: "internet-facing assets and telemetry-driven exposure discovery"},
	{Name: "Onyphe", Domain: "onyphe.io", Category: "Server", UseCase: "host intelligence, passive service discovery, and threat context"},
	{Name: "GreyNoise", Domain: "viz.greynoise.io", Category: "Threat Intelligence", UseCase: "background noise filtering and scanner activity triage"},
	{Name: "Censys", Domain: "censys.io", Category: "Server", UseCase: "certificates, hosts, services, and exposed infrastructure mapping"},
	{Name: "Hunter", Domain: "hunter.io", Category: "Email Addresses", UseCase: "email discovery, contact enumeration, and org profiling"},
	{Name: "FOFA", Domain: "fofa.info", Category: "Threat Intelligence", UseCase: "global asset discovery, banners, and exposure fingerprinting"},
	{Name: "ZoomEye", Domain: "zoomeye.org", Category: "Threat Intelligence", UseCase: "exposed hosts, devices, and service intelligence"},
	{Name: "LeakIX", Domain: "leakix.net", Category: "Threat Intelligence", UseCase: "exposed services, leaks, and weakly configured internet assets"},
	{Name: "Intelligence X", Domain: "intelx.io", Category: "OSINT", UseCase: "historical leaks, domain pivots, docs, and broader OSINT collection"},
	{Name: "Netlas", Domain: "app.netlas.io", Category: "Attack Surface", UseCase: "internet asset search, certificates, and attack surface mapping"},
	{Name: "Searchcode", Domain: "searchcode.com", Category: "Code Search", UseCase: "public code search for credentials, URLs, and vulnerable patterns"},
	{Name: "urlscan", Domain: "urlscan.io", Category: "Threat Intelligence", UseCase: "web infrastructure, related assets, and page behavior pivots"},
	{Name: "PublicWWW", Domain: "publicwww.com", Category: "Code Search", UseCase: "web source search for technologies, identifiers, and reused code"},
	{Name: "FullHunt", Domain: "fullhunt.io", Category: "Attack Surface", UseCase: "attack surface enumeration and internet-facing asset discovery"},
	{Name: "SOCRadar", Domain: "socradar.io", Category: "Threat Intelligence", UseCase: "threat exposure context and external attack surface monitoring"},
	{Name: "BinaryEdge", Domain: "binaryedge.io", Category: "Attack Surface", UseCase: "internet exposure search and infrastructure intelligence"},
	{Name: "IVRE", Domain: "ivre.rocks", Category: "Server", UseCase: "internet scan data exploration and host/service pivots"},
	{Name: "crt.sh", Domain: "crt.sh", Category: "Certificate Search", UseCase: "certificate transparency lookups for subdomain and org discovery"},
	{Name: "Vulners", Domain: "vulners.com", Category: "Vulnerabilities", UseCase: "CVE enrichment, exploit references, and software vulnerability matching"},
	{Name: "Pulsedive", Domain: "pulsedive.com", Category: "Threat Intelligence", UseCase: "IOC enrichment, threat context, and infrastructure pivots"},
}

var webSearchRecommendedSources = []Source{
	{Name: "Google", Domain: "google.com", Category: "Dorks", UseCase: "broad web discovery, indexed exposure checks, and targeted dorking"},
	{Name: "grep.app", Domain: "grep.app", Category: "Code Search", UseCase: "public code search for secrets, endpoints, and implementation clues"},
	{Name: "Searchcode", Domain: "searchcode.com", Category: "Code Search", UseCase: "public code search for credentials, URLs, and vulnerable patterns"},
	{Name: "PublicWWW", Domain: "publicwww.com", Category: "Code Search", UseCase: "web source search for technologies, identifiers, and reused code"},
	{Name: "crt.sh", Domain: "crt.sh", Category: "Certificate Search", UseCase: "certificate transparency lookups for subdomain and org discovery"},
	{Name: "urlscan", Domain: "urlscan.io", Category: "Threat Intelligence", UseCase: "web infrastructure, related assets, and page behavior pivots"},
}

func promptBlock(title string, sources []Source) string {
	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n")
	for _, src := range sources {
		b.WriteString("- ")
		b.WriteString(src.Domain)
		b.WriteString(" [")
		b.WriteString(src.Category)
		b.WriteString("]: ")
		b.WriteString(src.UseCase)
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

// AnalystPromptBlock returns sources the AI may recommend as analyst follow-up.
// These are references for operator guidance, not a claim of native product support.
func AnalystPromptBlock() string {
	return promptBlock("External analyst resources you may recommend when they fit the task:", RecommendedSources)
}

// WebSearchPromptBlock returns sources that are safe to target from web search engines.
func WebSearchPromptBlock(engine string) string {
	engine = strings.TrimSpace(strings.ToLower(engine))
	if engine == "" {
		engine = "google"
	}

	var b strings.Builder
	b.WriteString("Use only query syntax that is valid for ")
	b.WriteString(engine)
	b.WriteString(" web search.\n")
	b.WriteString("If you focus on one of these sources, do it with site filters or plain search terms only; do not use native Shodan/Censys/FOFA/etc. operators.\n")
	b.WriteString(promptBlock("Prefer web-search-friendly sources such as:", webSearchRecommendedSources))
	return strings.TrimSpace(b.String())
}
