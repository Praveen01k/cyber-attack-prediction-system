"""
Automated Incident Response & Mitigation Advisory Engine
Translates attack predictions into actionable SOC defensive playbooks,
firewall commands, and early warning risk alerts.
"""

MITIGATION_DATABASE = {
    'Normal': {
        'severity': 'LOW',
        'color': '#10B981', # emerald green
        'risk_score_base': 5,
        'description': 'Normal traffic pattern adhering to standard network RFC baselines.',
        'immediate_action': 'No defensive action needed. Routine telemetry logging active.',
        'firewall_rule': '# Traffic allowed under default egress/ingress policy\n# ACCEPT all legitimate packets',
        'early_warning': 'System operating under nominal parameters. Zero threat detected.'
    },
    'DoS': {
        'severity': 'HIGH',
        'color': '#EF4444', # red
        'risk_score_base': 92,
        'description': 'Denial of Service (DoS / SYN Flood) attempt detected. Abnormally elevated SYN error rates and zero payload return.',
        'immediate_action': 'Activate SYN Cookie protection, enable rate limiting, and quarantine offending source subnets.',
        'firewall_rule': '# Block anomalous SYN floods & rate limit connections\niptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP',
        'early_warning': 'CRITICAL WARNING: Imminent server resource exhaustion or packet flood detected. Triggering automated traffic throttling.'
    },
    'Probe': {
        'severity': 'MEDIUM',
        'color': '#F59E0B', # amber/yellow
        'risk_score_base': 68,
        'description': 'Port Scanning / Surveillance activity detected (Nmap, PortSweep). Host is systematically scanning destination services.',
        'immediate_action': 'Drop scanning IP packets, inspect firewall state table, and blacklist source subnet for 60 minutes.',
        'firewall_rule': '# Block port scanning probing host\niptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP\niptables -A INPUT -m recent --name portscan --rcheck --seconds 3600 -j DROP',
        'early_warning': 'ALERT: Reconnaissance activity detected. Attacker is mapping open ports and vulnerable entrypoints.'
    },
    'R2L': {
        'severity': 'CRITICAL',
        'color': '#DC2626', # deep red
        'risk_score_base': 96,
        'description': 'Remote to Local (R2L) unauthorized access attempt (SSH/FTP credential brute-forcing or password guessing).',
        'immediate_action': 'Immediately lock targeted user accounts, enforce IP whitelist, and require multi-factor authentication (MFA).',
        'firewall_rule': '# Throttle brute force SSH / FTP attempts via Fail2Ban / iptables\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP',
        'early_warning': 'URGENT EARLY WARNING: Credential stuffing / brute force attack in progress. Risk of unauthorized lateral movement.'
    },
    'U2R': {
        'severity': 'CRITICAL',
        'color': '#7F1D1D', # dark crimson
        'risk_score_base': 99,
        'description': 'User to Root (U2R) privilege escalation exploit detected (buffer overflow, unauthorized root shell invocation, su attempts).',
        'immediate_action': 'Isolate affected host immediately from corporate LAN. Revoke sudo/root privileges and initiate incident forensics.',
        'firewall_rule': '# Severe quarantine: isolate host from network\niptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT DROP',
        'early_warning': 'SECURITY BREACH WARNING: Potential root compromise / kernel exploit execution in progress. Immediate host isolation required!'
    }
}

def get_mitigation_plan(predicted_class: str, confidence: float = 0.9) -> dict:
    """Returns mitigation steps and formatted SOC advisory."""
    base = MITIGATION_DATABASE.get(predicted_class, MITIGATION_DATABASE['Normal'])
    
    # Calculate calibrated risk score
    risk = base['risk_score_base']
    if predicted_class != 'Normal':
        risk = min(100, int(risk * (0.8 + 0.2 * confidence)))
    else:
        risk = max(1, int(risk * (1.0 - 0.5 * confidence)))
        
    return {
        'class': predicted_class,
        'severity': base['severity'],
        'color': base['color'],
        'risk_score': risk,
        'description': base['description'],
        'immediate_action': base['immediate_action'],
        'firewall_rule': base['firewall_rule'],
        'early_warning': base['early_warning'],
        'confidence_pct': round(confidence * 100, 1)
    }
