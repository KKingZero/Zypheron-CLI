package tools

import (
	"encoding/json"
	"strings"
)

// parseNucleiOutput parses Nuclei JSON-line output into structured findings
func parseNucleiOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var findings []map[string]interface{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var finding map[string]interface{}
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue // Skip non-JSON lines
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		return nil
	}

	return map[string]interface{}{
		"findings": findings,
	}
}

// parseNiktoOutput parses Nikto output, extracting lines starting with +
func parseNiktoOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var findings []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "+") {
			// Remove the + prefix and trim
			finding := strings.TrimSpace(strings.TrimPrefix(line, "+"))
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		return nil
	}

	return map[string]interface{}{
		"findings": findings,
	}
}

// parseMasscanOutput parses Masscan output for discovered open ports
func parseMasscanOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var ports []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Discovered open port") {
			continue
		}

		// Format: Discovered open port 80/tcp on 192.168.1.1
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		ports = append(ports, map[string]string{
			"port": parts[3],
			"host": parts[5],
		})
	}

	if len(ports) == 0 {
		return nil
	}

	return map[string]interface{}{
		"open_ports": ports,
	}
}

// parseSQLMapOutput parses SQLMap output for injection findings
func parseSQLMapOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var findings []map[string]string
	lines := strings.Split(output, "\n")

	var current map[string]string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Parameter:") {
			if current != nil {
				findings = append(findings, current)
			}
			current = map[string]string{
				"parameter": strings.TrimSpace(strings.TrimPrefix(line, "Parameter:")),
			}
		} else if current != nil {
			if strings.HasPrefix(line, "Type:") {
				current["type"] = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			} else if strings.HasPrefix(line, "Title:") {
				current["title"] = strings.TrimSpace(strings.TrimPrefix(line, "Title:"))
			} else if strings.HasPrefix(line, "Payload:") {
				current["payload"] = strings.TrimSpace(strings.TrimPrefix(line, "Payload:"))
			} else if strings.HasPrefix(line, "Vector:") {
				current["vector"] = strings.TrimSpace(strings.TrimPrefix(line, "Vector:"))
			}
		}
	}

	if current != nil {
		findings = append(findings, current)
	}

	if len(findings) == 0 {
		return nil
	}

	return map[string]interface{}{
		"findings": findings,
	}
}

// parseSliverOutput parses Sliver C2 JSON output (sessions, beacons, implants)
func parseSliverOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	// Sliver supports --json flag, try parsing as JSON array or object
	var jsonArray []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &jsonArray); err == nil {
		return map[string]interface{}{
			"results": jsonArray,
			"count":   len(jsonArray),
		}
	}

	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(output), &jsonObj); err == nil {
		return jsonObj
	}

	// Fallback: parse text output for session/beacon lines
	var sessions []map[string]string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "ID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			sessions = append(sessions, map[string]string{
				"id":       fields[0],
				"name":     fields[1],
				"remote":   fields[2],
				"hostname": fields[3],
			})
		}
	}
	if len(sessions) > 0 {
		return map[string]interface{}{
			"sessions": sessions,
		}
	}
	return nil
}

// parseHavocOutput parses Havoc C2 operator console output
func parseHavocOutput(output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var callbacks []map[string]string
	var listeners []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse callback lines (demon checkins)
		if strings.Contains(line, "Callback") || strings.Contains(line, "checkin") || strings.Contains(line, "Demon") {
			fields := strings.Fields(line)
			entry := map[string]string{"raw": line}
			if len(fields) >= 2 {
				entry["agent"] = fields[0]
				entry["status"] = fields[len(fields)-1]
			}
			callbacks = append(callbacks, entry)
			continue
		}

		// Parse listener status lines
		if strings.Contains(line, "Listener") || strings.Contains(line, "listener") {
			fields := strings.Fields(line)
			entry := map[string]string{"raw": line}
			if len(fields) >= 3 {
				entry["name"] = fields[0]
				entry["type"] = fields[1]
				entry["status"] = fields[len(fields)-1]
			}
			listeners = append(listeners, entry)
		}
	}

	result := map[string]interface{}{}
	if len(callbacks) > 0 {
		result["callbacks"] = callbacks
	}
	if len(listeners) > 0 {
		result["listeners"] = listeners
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// parseStructuredOutput dispatches to the appropriate parser based on tool name
func parseStructuredOutput(tool, output string) interface{} {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	switch tool {
	case "nmap":
		return ParseNmapOutput(output)
	case "nuclei":
		return parseNucleiOutput(output)
	case "nikto":
		return parseNiktoOutput(output)
	case "masscan":
		return parseMasscanOutput(output)
	case "sqlmap":
		return parseSQLMapOutput(output)
	case "sliver":
		return parseSliverOutput(output)
	case "havoc":
		return parseHavocOutput(output)
	default:
		return nil
	}
}
