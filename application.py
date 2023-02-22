from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request
from random import random
from time import sleep
from threading import Thread, Event

from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import numpy as np
import pickle
import csv 
import traceback

import json
import pandas as pd

# from models.AE import *

from scipy.stats import norm

import ipaddress
from urllib.request import urlopen

from tensorflow import keras

from lime import lime_tabular

import dill

import joblib

import plotly
import plotly.graph_objs

import warnings
warnings.filterwarnings("ignore")

def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        #response from url(if res==None then check connection)
        data = json.load(res)
        #will load the json response into data
        return data['country']
    except Exception:
        return None
__author__ = 'hoang'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

#turn the flask app into a socketio app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

#random result Generator Thread
thread = Thread()
thread_stop_event = Event()

f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)
 

cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

ae_features = np.array(['FlowDuration',
'BwdPacketLengthMax',
'BwdPacketLengthMin',
'BwdPacketLengthMean',
'BwdPacketLengthStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets/s',
'PacketLengthMax',
'PacketLengthMean',
'PacketLengthStd',
'PacketLengthVariance',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AveragePacketSize',
'BwdSegmentSizeAvg',
'FWDInitWinBytes',
'BwdInitWinBytes',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns =cols)


src_ip_dict = {}

current_flows = {}
FlowTimeout = 600

#load models
# with open('models/scaler.pkl', 'rb') as f:
#     normalisation = pickle.load(f)

ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5')

with open('models/model.pkl', 'rb') as f:
    classifier = pickle.load(f)

with open('models/explainer', 'rb') as f:
    explainer = dill.load(f)
predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)

def classify(features):
    # preprocess
    global flow_count
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
    

    if feature_string[0] in src_ip_dict.keys():
        src_ip_dict[feature_string[0]] +=1
    else:
        src_ip_dict[feature_string[0]] = 1

    for i in [0,2]:
        ip = feature_string[i] #feature_string[0] is src, [2] is dst
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            if country is not None and country not in  ['ano', 'unknown']:
                img = ' <img src="static/images/blank.gif" class="flag flag-' + country.lower() + '" title="' + country + '">'
            else:
                img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
        else:
            img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        feature_string[i]+=img

    if np.nan in features:
        return

    # features = normalisation.transform([features])
    result = classifier.predict([features])
    proba = predict_fn_rf([features])
    proba_score = [proba[0].max()]
    proba_risk = sum(list(proba[0,1:]))
    if proba_risk >0.8: risk = ["<p style=\"color:red;\">Very High</p>"]
    elif proba_risk >0.6: risk = ["<p style=\"color:orangered;\">High</p>"]
    if proba_risk >0.4: risk = ["<p style=\"color:orange;\">Medium</p>"]
    if proba_risk >0.2: risk = ["<p style=\"color:green;\">Low</p>"]
    else: risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

    # x = K.process(features[0])
    # z_scores = round((x-m)/s,2)
    # p_values = norm.sf(abs(z_scores))*2


    classification = [str(result[0])]
    if result != 'Benign':
        print(feature_string + classification + proba_score )

    flow_count +=1
    w.writerow(['Flow #'+str(flow_count)] )
    w.writerow(['Flow info:']+feature_string)
    w.writerow(['Flow features:']+features)
    w.writerow(['Prediction:']+classification+ proba_score)
    w.writerow(['--------------------------------------------------------------------------------------------------'])

    w2.writerow(['Flow #'+str(flow_count)] )
    w2.writerow(['Flow info:']+features)
    w2.writerow(['--------------------------------------------------------------------------------------------------'])
    flow_df.loc[len(flow_df)] = [flow_count]+ record + classification + proba_score + risk


    ip_data = {'SourceIP': src_ip_dict.keys(), 'count': src_ip_dict.values()} 
    ip_data= pd.DataFrame(ip_data)
    ip_data=ip_data.to_json(orient='records')

    # socketio.emit('newresult', {'result': feature_string +[z_scores]+ classification, "ips": json.loads(ip_data)}, namespace='/test')
    # print(json.loads(ip_data))
    # # socketio.emit('newresult', {'result': feature_string + classification}, namespace='/test')
    # return feature_string +[z_scores]+ classification

    socketio.emit('newresult', {'result':[flow_count]+ feature_string + classification + proba_score + risk, "ips": json.loads(ip_data)}, namespace='/test')
    # socketio.emit('newresult', {'result': feature_string + classification}, namespace='/test')
    return [flow_count]+ record + classification+ proba_score + risk

def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        #print(p[TCP].flags, packet.getFINFlag(), packet.getSYNFlag(), packet.getPSHFlag(), packet.getACKFlag(),packet.getURGFlag() )

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:

            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def snif_and_detect():

    while not thread_stop_event.isSet():
        print("Begin Sniffing".center(20, ' '))
        # sniff(iface="en0", prn=newPacket)
        sniff(prn=newPacket)
        for f in current_flows.values():
            
            classify(f.terminated())


@app.route('/')
def index():
    #only by sending this page first will the client be connected to the socketio instance
    return render_template('index.html')

@app.route('/flow-detail')
def flow_detail():
    flow_id = request.args.get('flow_id', default = -1, type = int) #/flow-detail?flow_id=x
    # print(flow_id)
    flow = flow_df.loc[flow_df['FlowID'] == flow_id]
    # X = normalisation.transform([flow.values[0,1:40]])
    X = [flow.values[0,1:40]]
    choosen_instance = X
    proba_score = list(predict_fn_rf(choosen_instance))
    risk_proba =  sum(proba_score[0][1:])
    if risk_proba >0.8: risk = "Risk: <p style=\"color:red;\">Very High</p>"
    elif risk_proba >0.6: risk = "Risk: <p style=\"color:orangered;\">High</p>"
    if risk_proba >0.4: risk = "Risk: <p style=\"color:orange;\">Medium</p>"
    if risk_proba >0.2: risk = "Risk: <p style=\"color:green;\">Low</p>"
    else: risk = "Risk: <p style=\"color:limegreen;\">Minimal</p>"
    exp = explainer.explain_instance(choosen_instance[0], predict_fn_rf, num_features=6, top_labels = 1)

    X_transformed = ae_scaler.transform(X)
    reconstruct = ae_model.predict(X_transformed)
    err = reconstruct - X_transformed
    abs_err = np.absolute(err)
    
    ind_n_abs_largest = np.argpartition(abs_err, -5)[-5:]

    col_n_largest = ae_features[ind_n_abs_largest]
    # og_n_largest = X[ind_n_abs_largest]
    err_n_largest = err[0][ind_n_abs_largest]
    plot_div = plotly.offline.plot({
    "data": [
        plotly.graph_objs.Bar(x=col_n_largest[0].tolist(),y=err_n_largest[0].tolist())
    ]
    }, include_plotlyjs=False, output_type='div')

    # return render_template('detail.html',  tables=[flow.to_html(classes='data')], titles=flow.columns.values, explain = exp.as_html())

    return render_template('detail.html', tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')], exp=exp.as_html(), ae_plot = plot_div, risk = risk) # titles=flow.columns.values, classifier='RF Classifier'

# @app.route('/flow-detail')
# def flow_detail():
#     flow_id = request.args.get('flow_id', default = -1, type = int) #/flow-detail?flow_id=x
#     flow = flow_df.loc[flow_df['FlowID'] == flow_id].values[1:40]
#     print(flow)
#     print(type(flow))
#     X = normalisation.transform([flow])
#     explainer = lime.lime_tabular.LimeTabularExplainer(X,feature_names = cols, class_names=['Benign' 'Botnet' 'DDoS' 'DoS' 'FTP-Patator' 'Probe' 'SSH-Patator','Web Attack'],kernel_width=5)

#     choosen_instance = X
#     exp = explainer.explain_instance(choosen_instance, predict_fn_rf,num_features=10)
#     # exp.show_in_notebook(show_all=False)




@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread
    print('Client connected')

    #Start the random result generator thread only if the thread has not been started before.
    if not thread.is_alive():
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    socketio.run(app)
