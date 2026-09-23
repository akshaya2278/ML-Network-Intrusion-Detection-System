import os
import pandas as pd
import numpy as np
import requests

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", 
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", 
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", 
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", 
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", 
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", 
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", 
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", 
    "label", "difficulty_level"
]

ATTACK_MAPPING = {
    'normal': 'normal',
    # DoS
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS', 'land': 'DoS', 
    'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
    # Probe
    'portsweep': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'satan': 'Probe', 
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L', 
    'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 
    'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'rootkit': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
}

def download_file(url, filename):
    if not os.path.exists(filename):
        print(f"Downloading {filename}...")
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(filename, 'w') as f:
                f.write(response.text)
        except Exception as e:
            print(f"Download failed: {e}. Generating synthetic fallback data...")
            generate_synthetic_data(filename)

def generate_synthetic_data(filename):
    """Fallback if NSL-KDD download fails."""
    np.random.seed(42)
    rows = 5000
    df = pd.DataFrame({
        "duration": np.random.randint(0, 1000, rows),
        "protocol_type": np.random.choice(['tcp', 'udp', 'icmp'], rows),
        "service": np.random.choice(['http', 'private', 'domain_u', 'smtp'], rows),
        "flag": np.random.choice(['SF', 'S0', 'REJ'], rows),
        "src_bytes": np.random.randint(0, 5000, rows),
        "dst_bytes": np.random.randint(0, 5000, rows),
        "label": np.random.choice(list(ATTACK_MAPPING.keys())[:10], rows),
        "difficulty_level": np.random.randint(18, 21, rows)
    })
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    df = df[COLUMNS]
    df.to_csv(filename, index=False, header=False)

def load_and_prep_data():
    download_file(TRAIN_URL, "train.csv")
    download_file(TEST_URL, "test.csv")

    df_train = pd.read_csv("train.csv", names=COLUMNS)
    df_test = pd.read_csv("test.csv", names=COLUMNS)

    for df in [df_train, df_test]:
        df.drop(columns=['difficulty_level'], inplace=True, errors='ignore')
        df.drop_duplicates(inplace=True)
        # Map specific attacks to broad categories; unknown attacks go to 'unknown'
        df['attack_category'] = df['label'].map(ATTACK_MAPPING).fillna('unknown')
        df['is_suspicious'] = (df['attack_category'] != 'normal').astype(int)

    return df_train, df_test