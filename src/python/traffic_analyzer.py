import pickle
import dill
import pandas
import matplotlib.pyplot as plt
from lime import lime_tabular

all_col = [
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
    "idle_mean", "idle_std", "idle_max", "idle_min"
]

ddos_col = ["flow_byts_s", "flow_pkts_s", "flow_iat_mean", "fwd_iat_mean", "bwd_iat_mean", "pkt_len_mean", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "init_fwd_win_bytes", "active_mean", "idle_mean"]

sel_column = ddos_col

class TrafficAnalyzer:
    def __init__(self, model_path, label_encoder_path, lime_path):

        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        #with open(label_encoder_path, 'rb') as f:
        #    self.label_encoder = pickle.load(f)

        with open(lime_path, 'rb') as f:
            self.explainer = dill.load(f)

        print(self.model.classes_)

    def get_prediction(self, data):

        df = pandas.DataFrame([data])

        df = df[sel_column]

        #try:
            #explanation = self.explainer.explain_instance(
            #    data_row=df.iloc[0].values,  # Reshape to a 2D array
            #    predict_fn=self.model.predict_proba,
            #    num_features=len(sel_column)
            #)

            # Plot the explanation
            #fig = explanation.as_pyplot_figure()
            #plt.tight_layout()
            #plt.show()
        #except Exception as e:
            #print(e)

        result = self.model.predict_proba(df[sel_column].values)
        #result_2 = self.model.predict(df)
        #result_label = self.label_encoder.inverse_transform(result)
        #result_output = f"{str(flow_info):<10} : {str(result_2):<3} : {str(result):<10}"
        return result