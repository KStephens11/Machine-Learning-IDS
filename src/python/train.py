import pickle
import dill
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
import numpy as np

import matplotlib.pyplot as plt
from lime import lime_tabular

# Define columns and other parameters
all_cols = [
    "dst_port", "proto", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "total_fwd_pkt_len", "total_bwd_pkt_len",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max",
    "flow_iat_min", "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
    "fwd_iat_min", "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max",
    "bwd_iat_min", "fwd_psh_flag", "bwd_psh_flag", "fwd_urg_flag", "bwd_urg_flag",
    "fwd_header_len", "bwd_header_len", "flow_fwd_pkts_s", "flow_bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "urg_flag_cnt", "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts", "subflow_bwd_bytes",
    "init_fwd_win_bytes", "init_bwd_win_bytes", "fwd_act_data_pkts",
    "fwd_seg_size_min", "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min", "label"
]

# before dest port is new
ddos_col = ["flow_byts_s", "flow_pkts_s", "flow_iat_mean", "fwd_iat_mean", "bwd_iat_mean", "pkt_len_mean", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "init_fwd_win_bytes", "active_mean", "idle_mean", "label"]

sel_column = ddos_col

# Initialize LabelEncoder and RandomForest
label_encoder = LabelEncoder()
rf = RandomForestClassifier()

print("Loading Dataset...")
#df = pd.read_csv("data/Thursday-20-02-2018_TrafficForML_CICFlowMeter.csv") #DDOS - LOIC - HTTP
df = pd.read_csv("data/custom_data/combined.csv")

# Drop unnecessary columns and set column names
#df = df.drop(columns=["Timestamp", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
#                            "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
#                            "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"])


df.columns = all_cols

df = df[ddos_col]

#df = df.drop(columns=["fwd_seg_size_min","init_fwd_win_bytes","init_bwd_win_bytes","rst_flag_cnt","ack_flag_cnt","bwd_psh_flag","fwd_pkt_len_mean","fwd_act_data_pkts","fwd_header_len"])

# Handle infinite values and missing data
df.replace([np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

# Encode the label column
#df['label'] = label_encoder.fit_transform(df['label'])

# Split into features and labels
X = df.drop('label', axis=1)
y = df['label']

print("Finished Loading Dataset.")

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X.values, y.values, test_size=0.33, random_state=42)

print("Training...")

# Train the RandomForest model
rf.fit(X_train, y_train)

#param_grid = {
#    'n_estimators': [100, 200],  
#    'max_depth': [10, 20],  
#   'min_samples_split': [2, 5],  
#    'min_samples_leaf': [1, 2],  
#    'max_features': ['sqrt']
#}

#grid = GridSearchCV(rf, param_grid=param_grid, cv=5)
#grid.fit(X_train, y_train)

print("Finished Training.")

# Evaluate and print the model's performance
print(rf.score(X_test, y_test))
#print(grid.best_params_)
#print(grid.score(X_test, y_test))


explainer = lime_tabular.LimeTabularExplainer(
    mode='classification',
    training_data=X_train,
    training_labels=y_train,
    feature_names=X.columns.tolist(),
    class_names=rf.classes_,  # Pass the label encoder's classes
    discretize_continuous=True  # Discretize continuous values for interpretability
)

print("Making Pickles...")

# Save the trained model and label encoder to disk
with open('model/rf_ddos.pkl', 'wb') as model_file:
    pickle.dump(rf, model_file)

#with open('model/le_ddos.pkl', 'wb') as encoder_file:
#    pickle.dump(label_encoder, encoder_file)

with open('model/lime_explainer_ddos.pkl', 'wb') as explainer_file:
    dill.dump(explainer , explainer_file)

print("Finished Making Pickles.")
