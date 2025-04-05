import pickle
import dill

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.naive_bayes import GaussianNB

from sklearn.preprocessing import LabelEncoder

from sklearn.preprocessing import MinMaxScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split, GridSearchCV

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

from lime import lime_tabular

# Define columns and other parameters
sel_cols = [
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

label_encoder = LabelEncoder()

# Initialize  RandomForest
rf = RandomForestClassifier()
lg = LogisticRegression(max_iter=1000)
dt = DecisionTreeClassifier()
kn = KNeighborsClassifier()
gnb = GaussianNB()
gb = GradientBoostingClassifier()

model = xgb

print("Loading Dataset...")
df = pd.read_csv("data/model_datasets_no_0/Combined.csv")

# Drop unnecessary columns and set column names
#df = df.drop(columns=["Timestamp", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
#                            "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
#                            "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"])


df.columns = sel_cols

#df = df[ddos_col]

#df = df.drop(columns=["fwd_seg_size_min","init_fwd_win_bytes","init_bwd_win_bytes","rst_flag_cnt","ack_flag_cnt","bwd_psh_flag","fwd_pkt_len_mean","fwd_act_data_pkts","fwd_header_len"])

# Handle infinite values and missing data
df.replace([np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

# Split into features and labels
X = df.drop('label', axis=1)
y = df['label']

print("Finished Loading Dataset.")


# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X.values, y.values, test_size=0.33, random_state=42)

pipe = make_pipeline(MinMaxScaler(feature_range=(-1, 1)), model)

print("Training...")

# Train the RandomForest model
pipe.fit(X_train, y_train)

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
print(pipe.score(X_test, y_test))


#explainer = lime_tabular.LimeTabularExplainer(
#    mode='classification',
#    training_data=X_train,
#    training_labels=y_train,
#    feature_names=X.columns.tolist(),
#    class_names=pipe.classes_,  # Pass the label encoder's classes
#    discretize_continuous=True  # Discretize continuous values for interpretability
#)

print("Making Pickles...")

# Save the trained model and label encoder to disk
with open('model/model.pkl', 'wb') as model_file:
    pickle.dump(pipe, model_file)

#with open('model/model_lime.pkl', 'wb') as explainer_file:
#    dill.dump(explainer , explainer_file)

print("Finished Making Pickles.")
