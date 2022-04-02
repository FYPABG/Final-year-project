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
		df.rename(columns = {  
		 			'fwd_pkt_len_max':'Fwd Packet Length Max',
					'fwd_pkt_len_min':'Fwd Packet Length Min',
					'pkt_len_max':'Max Packet Length',
					'pkt_len_min':'Min Packet Length',
					'pkt_size_avg':'Average Packet Size', 
					'fwd_pkts_s':'FWD Packets/s',
					'fwd_header_len':'Fwd Header Length',
					'fwd_seg_size_min':'Min Seg Size Forward',
					'fwd_pkt_len_std':'Fwd Packet Length std'
					}, inplace = True)   
						 
		df = df[["Fwd Packet Length Max","Fwd Packet Length Min" ,"Max Packet Length" ,"Min Packet Length"
                         ,"Average Packet Size","FWD Packets/s","Fwd Header Length","Min Seg Size Forward",
                         "Fwd Packet Length std" ]]

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
        if check > 0.65:  # change to 0 to force ddos attack
            hostile += 1
        else:
            safe += 1
    print("Safe Packets: ", safe)
    print("Possible Hostile Packets: ", hostile)
    print("Percentage of Hostile packets : ", 100 * hostile / (safe + hostile))
    print("\n")
    if hostile >= ((safe + hostile) / 2):
        print('Attack Detected at: '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        print('Packets collected: '+str(safe + hostile))
        print("\n")
    else:
        print('Normal Activity Detected at: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        print('Packets collected: ' + str(safe+hostile))
        print("\n")

if __name__ == '__main__':
    iteration = 1
    modelname = "models/binary_classifier1.h5"
    loaded_model = load_model(modelname)
    lmlp = loaded_model
    while(True):
	    data = data_generation(iteration)
	    if(data is not None):
                model_prediction(lmlp,data)  
	    if os.path.exists("csvs/test-"+str(iteration)+".csv"):
		    os.remove("csvs/test-"+str(iteration)+".csv")
		    iteration += 1

