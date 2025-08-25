# Machine-Learning-IDS

A Network Intrusion Detection System using machine learning to classify network attacks and present results via a web interface.

Captures packets from a NIC, parses them for data, processes the data for features modelled after the CSE-CIC-IDS2018 dataset, which are then fed into machine learning models (Random Forest, Linear Regression) to classify traffic as benign or malicious, identifying attack types such as DDoS and brute force.

