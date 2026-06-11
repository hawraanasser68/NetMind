FEATURE_COLUMNS = [
    # Volume
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    # Rate
    'Flow Byts/s',
    'Flow Pkts/s',
    'Fwd Pkts/s',
    'Bwd Pkts/s',
    # Timing
    'Flow Duration',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    # Active/Idle
    'Active Mean',
    'Active Std',
    'Idle Mean',
    'Idle Std',
    # TCP Flags
    'SYN Flag Cnt',
    'FIN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'URG Flag Cnt',
    # Packet size
    'Pkt Len Mean',
    'Pkt Len Std',
    'Down/Up Ratio',
    # Derived (computed before feeding to model)
    'byte_ratio',
    'proto_tcp',
    'proto_udp',
    'proto_icmp',
    'is_privileged_port',
]

TARGET_COLUMN = 'label'
N_FEATURES    = 33
N_CLASSES     = 3

LABEL_MAP = {
    'Benign':                   0,
    'Infilteration':            1,
    # Brute force
    'FTP-BruteForce':           2,
    'SSH-Bruteforce':           2,
    'Brute Force -Web':         2,
    'BruteForce-Web':           2,
    'Brute Force -XSS':         2,
    'BruteForce-XSS':           2,
    # Injection
    'SQL Injection':            2,
    'SQL-Injection':            2,
    # DoS
    'DoS attacks-GoldenEye':    2,
    'DoS-GoldenEye':            2,
    'DoS attacks-SlowHTTPTest': 2,
    'DoS-Slowhttptest':         2,
    'DoS attacks-Hulk':         2,
    'DoS-Hulk':                 2,
    'DoS attacks-Slowloris':    2,
    'DoS-Slowloris':            2,
    # DDoS
    'DDoS attacks-LOIC-HTTP':   2,
    'DDoS-LOIC-HTTP':           2,
    'DDOS attack-LOIC-UDP':     2,
    'DDoS-LOIC-UDP':            2,
    'DDOS attack-HOIC':         2,
    'DDoS-HOIC':                2,
    # Other
    'Bot':                      2,
    'Heartbleed':               2,
}

CLASS_NAMES = {0: 'benign', 1: 'suspicious', 2: 'attack'}

CLEANING_RULES = {
    'drop_negative_duration': True,
    'replace_inf_with_zero':  True,
    'fill_nulls_with_zero':   True,
}

RATE_COLUMNS = ['Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s']

assert len(FEATURE_COLUMNS) == N_FEATURES, \
    f'Feature contract broken: expected {N_FEATURES}, got {len(FEATURE_COLUMNS)}'
