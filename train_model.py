import glob
import numpy as np
import pandas as pd

# from sklearn.preprocessing import MinMaxScaler
# from sklearn.model_selection import train_test_split



def dataset():
    '''
    path = 'ML'
    all_files = glob.glob(path + '/*.csv')
    dataset1 = pd.concat((pd.read_csv(f, header=None) for f in all_files))

    col_names = ['Destination_Port', 'Flow_Duration', 'Bwd_Packet_Length_Max',
                 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
                 'Bwd_Packet_Length_Std', 'Flow_IAT_Mean', 'Flow_IAT_Std',
                 'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
                 'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total',
                 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
                 'Fwd_PSH_Flags', 'Fwd_Packets_s', 'Max_Packet_Length',
                 'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance',
                 'FIN_Flag_Count', 'SYN_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count',
                 'URG_Flag_Count', 'Average_Packet_Size', 'Avg_Bwd_Segment_Size',
                 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Active_Min',
                 'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min', 'Label']
    dataset1.columns = col_names
    '''

    path = 'MachineLearningCVE'
    path = 'C:\\Users\\Lenovo\\Desktop\\ids\\MachineLearningCVE'
    all_files = glob.glob(path + "/*.csv")
    dataset2 = pd.concat((pd.read_csv(f, low_memory=False) for f in all_files))

    col_names = ["Destination_Port",
                 "Flow_Duration",
                 "Total_Fwd_Packets",
                 "Total_Backward_Packets",
                 "Total_Length_of_Fwd_Packets",
                 "Total_Length_of_Bwd_Packets",
                 "Fwd_Packet_Length_Max",
                 "Fwd_Packet_Length_Min",
                 "Fwd_Packet_Length_Mean",
                 "Fwd_Packet_Length_Std",
                 "Bwd_Packet_Length_Max",
                 "Bwd_Packet_Length_Min",
                 "Bwd_Packet_Length_Mean",
                 "Bwd_Packet_Length_Std",
                 "Flow_Bytes_s",
                 "Flow_Packets_s",
                 "Flow_IAT_Mean",
                 "Flow_IAT_Std",
                 "Flow_IAT_Max",
                 "Flow_IAT_Min",
                 "Fwd_IAT_Total",
                 "Fwd_IAT_Mean",
                 "Fwd_IAT_Std",
                 "Fwd_IAT_Max",
                 "Fwd_IAT_Min",
                 "Bwd_IAT_Total",
                 "Bwd_IAT_Mean",
                 "Bwd_IAT_Std",
                 "Bwd_IAT_Max",
                 "Bwd_IAT_Min",
                 "Fwd_PSH_Flags",
                 "Bwd_PSH_Flags",
                 "Fwd_URG_Flags",
                 "Bwd_URG_Flags",
                 "Fwd_Header_Length",
                 "Bwd_Header_Length",
                 "Fwd_Packets_s",
                 "Bwd_Packets_s",
                 "Min_Packet_Length",
                 "Max_Packet_Length",
                 "Packet_Length_Mean",
                 "Packet_Length_Std",
                 "Packet_Length_Variance",
                 "FIN_Flag_Count",
                 "SYN_Flag_Count",
                 "RST_Flag_Count",
                 "PSH_Flag_Count",
                 "ACK_Flag_Count",
                 "URG_Flag_Count",
                 "CWE_Flag_Count",
                 "ECE_Flag_Count",
                 "Down_Up_Ratio",
                 "Average_Packet_Size",
                 "Avg_Fwd_Segment_Size",
                 "Avg_Bwd_Segment_Size",
                 "Fwd_Header_Length",
                 "Fwd_Avg_Bytes_Bulk",
                 "Fwd_Avg_Packets_Bulk",
                 "Fwd_Avg_Bulk_Rate",
                 "Bwd_Avg_Bytes_Bulk",
                 "Bwd_Avg_Packets_Bulk",
                 "Bwd_Avg_Bulk_Rate",
                 "Subflow_Fwd_Packets",
                 "Subflow_Fwd_Bytes",
                 "Subflow_Bwd_Packets",
                 "Subflow_Bwd_Bytes",
                 "Init_Win_bytes_forward",
                 "Init_Win_bytes_backward",
                 "act_data_pkt_fwd",
                 "min_seg_size_forward",
                 "Active_Mean",
                 "Active_Std",
                 "Active_Max",
                 "Active_Min",
                 "Idle_Mean",
                 "Idle_Std",
                 "Idle_Max",
                 "Idle_Min",
                 "Label"
                 ]
    dataset2.columns = col_names

    dataset2 = dataset2[[#'Destination_Port', 
                            'Flow_Duration', 'Bwd_Packet_Length_Max',
                         'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
                         'Bwd_Packet_Length_Std', 'Flow_IAT_Mean', 'Flow_IAT_Std',
                         'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
                         'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total',
                         'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
                         'Fwd_PSH_Flags', 'Fwd_Packets_s', 'Max_Packet_Length',
                         'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance',
                         'FIN_Flag_Count', 'SYN_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count',
                         'URG_Flag_Count', 'Average_Packet_Size', 'Avg_Bwd_Segment_Size',
                         'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Active_Min',
                         'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min', 'Label']]

    dataset2 = dataset2.replace(['Heartbleed', 'Web Attack � Sql Injection', 'Infiltration'], np.nan)
    dataset2 = dataset2.dropna()
    attack_group = {'BENIGN': 'Benign',
                    'DoS Hulk': 'DoS',
                    'PortScan': 'Probe',
                    'DDoS': 'DDoS',
                    'DoS GoldenEye': 'DoS',
                    'FTP-Patator': 'FTP-Patator',
                    'SSH-Patator': 'SSH-Patator',
                    'DoS slowloris': 'DoS',
                    'DoS Slowhttptest': 'DoS',
                    'Bot': 'Botnet',
                    'Web Attack � Brute Force': 'Web Attack',
                    'Web Attack � XSS': 'Web Attack'}
    dataset2['Label'] = dataset2.Label.map(lambda x: attack_group[x])

    # result = pd.concat([dataset1, dataset2], axis=0, join='outer', ignore_index=False, keys=None,levels=None, names=None, verify_integrity=False, copy=True)

    dataset2 = dataset2.replace([np.inf, -np.inf], np.nan)
    dataset2 = dataset2.dropna()

    xs = dataset2[[#'Destination_Port', 
                        'Flow_Duration', 'Bwd_Packet_Length_Max',
                         'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
                         'Bwd_Packet_Length_Std', 'Flow_IAT_Mean', 'Flow_IAT_Std',
                         'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
                         'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total',
                         'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
                         'Fwd_PSH_Flags', 'Fwd_Packets_s', 'Max_Packet_Length',
                         'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance',
                         'FIN_Flag_Count', 'SYN_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count',
                         'URG_Flag_Count', 'Average_Packet_Size', 'Avg_Bwd_Segment_Size',
                         'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Active_Min',
                         'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min']]

    ys = dataset2['Label']
    #normalise
    # min_max_scaler = MinMaxScaler().fit(xs)
    # xs = min_max_scaler.transform(xs)

    return xs.values, ys#, min_max_scaler

'''
    x_train, x_test, y_train, y_test = train_test_split(xs, ys, test_size=0.8, random_state=0,
                                                        stratify=ys)

    # normalise
    min_max_scaler = MinMaxScaler().fit(x_train)
    x_train = min_max_scaler.transform(x_train)
    x_test = min_max_scaler.transform(x_test)

    # learn

    return x_train, x_test, y_train, y_test, min_max_scaler
    
    
'''

from sklearn.ensemble import RandomForestClassifier


import pickle

import warnings
warnings.filterwarnings("ignore")


global X 
global Y
# global normalisation
global classifier



def main():
    print(" Training ".center(20, '~'))
    global X, Y, classifier
    x_train, y_train = dataset()
    X = x_train
    Y = y_train
    # normalisation = min_max_scaler

    classifier = RandomForestClassifier()
    classifier = classifier.fit(X, Y)

    # save
    # with open('models/scaler.pkl','wb') as f:
    #     pickle.dump(normalisation,f)

    with open('models/model.pkl','wb') as f:
        pickle.dump(classifier,f)




if __name__ == '__main__':
    main()