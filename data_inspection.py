import pandas as pd
#df = pd.read_csv('Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')

import kagglehub
import os


import os
import kagglehub

path = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv")
print("Dataset path:", path)
print("\nAll files:")
for f in sorted(os.listdir(path)):
    size = os.path.getsize(os.path.join(path, f)) / 1024 / 1024
    print(f"  {f}  ({size:.1f} MB)")

for filename in ['02-20-2018.csv', '02-21-2018.csv', '03-02-2018.csv']:
    df_temp = pd.read_csv(os.path.join(path, filename), 
                          low_memory=False, nrows=1000)
    print(f"\n{filename}:")
    print(df_temp['Label'].value_counts())
    
        
# Download latest version
path = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv")
df = pd.read_csv(os.path.join(path, "02-14-2018.csv"), low_memory=False)

print("Path to dataset files:", path)
print(df.columns.tolist())
print(df.shape)
print(df['Label'].value_counts())

import numpy as np

# ── 1. Check for infinite and null values ─────────────────────────────────────
print("\n=== Infinite Values ===")
inf_counts = df.isin([np.inf, -np.inf]).sum()
print(inf_counts[inf_counts > 0])

print("\n=== Null Values ===")
null_counts = df.isnull().sum()
print(null_counts[null_counts > 0])

# ── 2. Check the columns we plan to use ───────────────────────────────────────
planned_features = [
    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Active Mean', 'Active Std', 'Idle Mean', 'Idle Std',
    'SYN Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'Pkt Len Mean', 'Pkt Len Std', 'Down/Up Ratio',
    'Dst Port', 'Protocol',
]

print("\n=== Planned Features — Present in Dataset? ===")
for f in planned_features:
    status = "✓" if f in df.columns else "✗ MISSING"
    print(f"  {status}  {f}")

# ── 3. Check rate columns specifically (known to have inf) ────────────────────
print("\n=== Rate Column Stats (check for inf) ===")
rate_cols = ['Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s']
for col in rate_cols:
    if col in df.columns:
        inf_count = np.isinf(df[col]).sum()
        print(f"  {col}: inf={inf_count}, mean={df[col].replace([np.inf, -np.inf], np.nan).mean():.2f}")

# ── 4. Protocol distribution ──────────────────────────────────────────────────
print("\n=== Protocol Distribution ===")
print(df['Protocol'].value_counts())

# ── 5. Dst Port distribution ──────────────────────────────────────────────────
print("\n=== Dst Port — Top 20 ===")
print(df['Dst Port'].value_counts().head(20))

# ── 6. Flow Duration sanity check ─────────────────────────────────────────────
print("\n=== Flow Duration Stats ===")
print(df['Flow Duration'].describe())
zero_duration = (df['Flow Duration'] == 0).sum()
print(f"  Zero duration flows: {zero_duration}")

print((df['Flow Duration'] < 0).sum())