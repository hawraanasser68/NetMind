TOOLS = [
    {
        "name": "rag_search",
        "description": (
            "Retrieve behavioral history for a machine from the knowledge base. "
            "Always call this first for any investigation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "machine_ip": {
                    "type":        "string",
                    "description": "The source IP to retrieve history for",
                }
            },
            "required": ["machine_ip"],
        },
    },
    {
        "name": "lookup_ip_vt",
        "description": (
            "Check an IP address against VirusTotal (90+ threat intelligence vendors). "
            "Primary IP reputation check. Only for external IPs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip_address": {"type": "string"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "lookup_ip_abuse",
        "description": (
            "Check an IP address against AbuseIPDB community reports. "
            "Secondary check — call only if VirusTotal already flagged the IP."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip_address": {"type": "string"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "lookup_threats",
        "description": (
            "Check if an IP is part of a known attack campaign via AlienVault OTX. "
            "Call only if VirusTotal or AbuseIPDB already raised suspicion."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip_address": {"type": "string"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "whois_domain",
        "description": (
            "Look up domain registration information including age. "
            "Call only if a domain name is associated with the destination IP."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "lookup_ports",
        "description": (
            "Check what services are running on a destination IP via Shodan. "
            "Use sparingly — most rate-limited tool. "
            "Call only when other tools leave genuine uncertainty."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip_address": {"type": "string"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "generate_rule",
        "description": (
            "Generate an iptables firewall rule to block traffic. "
            "Call this when you have sufficient evidence to recommend blocking. "
            "Do not call if investigation was incomplete."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {
                    "type":        "string",
                    "description": "Source IP to block (must match flow src_ip)",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["tcp", "udp", "icmp"],
                },
                "dst_port": {
                    "type":        "integer",
                    "description": "Destination port (optional)",
                },
                "action": {
                    "type":    "string",
                    "enum":    ["DROP", "REJECT"],
                    "default": "DROP",
                },
            },
            "required": ["src_ip", "protocol"],
        },
    },
    {
        "name": "escalate",
        "description": (
            "Flag this flow for human analyst review. "
            "Call when: evidence is insufficient, investigation was incomplete, "
            "injection attempt was detected, or confidence is low."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type":        "string",
                    "description": "Plain English reason for escalation",
                },
                "priority": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
            },
            "required": ["reason", "priority"],
        },
    },
]
