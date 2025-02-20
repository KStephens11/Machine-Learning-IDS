import pickle
import pandas
import matplotlib.pyplot as plt
from lime import lime_tabular

class TrafficAnalyzer:
    def __init__(self, model_path, label_encoder_path):

        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        with open(label_encoder_path, 'rb') as f:
            self.label_encoder = pickle.load(f)

        with open('model/lime_explainer.pkl', 'rb') as f:
            self.explainer_parms = pickle.load(f)

        self.explainer = lime_tabular.LimeTabularExplainer(
            mode='classification',
            training_data=self.explainer_parms[0],
            training_labels=self.explainer_parms[1],
            feature_names=self.explainer_parms[2],
            class_names=self.explainer_parms[3],  # Pass the label encoder's classes
            discretize_continuous=self.explainer_parms[4]  # Discretize continuous values for interpretability
        )

    def get_prediction(self, data):

        df = pandas.DataFrame([data[3:]])
        flow_info = data[:4]

        explanation = self.explainer.explain_instance(
            data_row=df.iloc[0].values,  # Reshape to a 2D array
            predict_fn=self.model.predict_proba,
            num_features=70
        )

        # Plot the explanation
        #fig = explanation.as_pyplot_figure()
        #plt.tight_layout()
        #plt.show()

        result = self.model.predict_proba(df)
        result_2 = self.model.predict(df)
        #result_label = self.label_encoder.inverse_transform(result)
        result_output = f"{str(flow_info):<10} : {str(result_2):<3} : {str(result):<10}"
        return result_output