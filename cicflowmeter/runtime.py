#import pyshark
#from nfstream import NFStreamer
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import datetime
import os
#import socket
from sniffer import main
from keras.models import load_model



def data_generation(iteration):  # allows the user to choose interface
    print("Capturing Network Traffic")
    main(iteration)
    return feature_extraction(iteration)


def feature_extraction(file_no):
	try:
		print("Extracting Features")
		df = pd.read_csv("csvs/test-"+str(file_no)+".csv")
		#df['Flow ID'] = df.apply(lambda row:
		#	    str(row.src_ip) + '-' + str(row.dst_ip) + '-' + str(row.src_port)
		#	     + '-' + str(row.dst_port)+'-'+str(row.protocol)
		#	    if row.src_ip > row.dst_ip
		#	    else str(row.dst_ip) + '-' + str(row.src_ip) + '-' + str(row.dst_port) 
		#	    + '-' + str(row.src_port) + '-' + str(row.protocol) , axis=1)				
		df.rename(columns = {  'ack_flag_cnt':'ACK Flag Cnt', 
		                       'fwd_seg_size_min':'Fwd Seg Size Min',
					'protocol':'Protocol',
					'init_bwd_win_byts':'Init Bwd Win Byts',
					'psh_flag_cnt':'PSH Flag Cnt',
					'syn_flag_cnt':'SYN Flag Cnt',
					'fwd_urg_flags':'CWE Flag Count',
					'ece_flag_cnt':'ECE Flag Cnt',
					'urg_flag_cnt':'URG Flag Cnt',
					'fwd_pkt_len_max':'Fwd Pkt Len Max',
					'init_fwd_win_byts':'Init Fwd Win Byts',
					'flow_duration':'Flow Duration',
					}, inplace = True)   
						 
		df = df[['ACK Flag Cnt', 'Fwd Seg Size Min', 'Protocol', 'Init Bwd Win Byts', 'PSH Flag Cnt', 'SYN Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'URG Flag Cnt', 'Fwd Pkt Len Max', 'Init Fwd Win Byts', 'Flow Duration']]

		df.columns = df.columns.str.replace(' ', '')
		#data = LiveLabelEncoding(df)
		print("Features Extracted...!")
		return df		
	except Exception as e:
		print(e)
		return None


def LiveLabelEncoding(data):  # same as LabelEncoding(), but use for realtime
	try:
		le_fid = LabelEncoder()
		le_fid.fit(data['FlowID'])
		data['FlowID'] = le_fid.fit_transform(data['FlowID'])

		le_sip = LabelEncoder()
		le_sip.fit(data['SrcIP'])
		data['SrcIP'] = le_sip.fit_transform(data['SrcIP'])

		le_dip = LabelEncoder()
		le_dip.fit(data['DstIP'])
		data['DstIP'] = le_dip.fit_transform(data['DstIP'])

		return data
	except Exception as e:
		print(e)
		return None


def model_prediction(lmlp,data):
    print("Processing Data", "\n")
    ss = StandardScaler()
    data = ss.fit_transform(data)
    predictions = lmlp.predict(data)
    hostile = 0  # this block counts how many 'hostile' packets have been predicted by the model
    safe = 0
    for check in predictions:
        if check > 0.75:  # change to 0 to force ddos attack
            hostile += 1
        else:
            safe += 1
    print("Safe Packets: ", safe)
    print("Possible Hostile Packets: ", hostile)
    print(100 * hostile / (safe + hostile))
    print("\n")
    if hostile >= ((safe + hostile) / 2):
        print('Attack Detected at: '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        print('Packets collected: '+str(safe + hostile))
    else:
        print('Normal Activity Detected at: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        print('Packets collected: ' + str(safe+hostile))


if __name__ == '__main__':
    iteration = 1
    modelname = "models/binary_classifier.h5"
    loaded_model = load_model(modelname)
    lmlp = loaded_model
    while(True):
	    data = data_generation(iteration)
	    if(data is not None):
                model_prediction(lmlp,data)  
	    if os.path.exists("csvs/test-"+str(iteration)+".csv"):
		    os.remove("csvs/test-"+str(iteration)+".csv")
		    iteration += 1

