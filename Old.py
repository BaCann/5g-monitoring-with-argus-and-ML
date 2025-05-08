from argus_tool import argus, argus_client
import time
import logging
import datetime
import pytz
from joblib import load
import pandas as pd
import os
import csv 
import pickle
import io
import string


APP_NAME = "ArgusTest"
INTERFACE = "lo"
DURATION = 60

if __name__ == "__main__":
    # Mở file .pkl ở chế độ đọc nhị phân
    with open('rf_model.pkl', 'rb') as file:
        rf_model = pickle.load(file)

    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    started, process = argus.start_argus(
        path_to_argus='/usr/local/sbin/argus',
        interface=INTERFACE,
        server_port=561
    )

    if not started:
        logger.warning(f"The argus server is running PID = {process}.")
    else:
        while True:
            logger.info("Waiting for the argus server ...")
            time.sleep(3)

            is_running, pid = argus.is_argus_running()
            if is_running:
                logger.info(f"The argus server is running PID = {pid}.")
                break
    # Record Start time
    start_time = datetime.datetime.now()
    print('-'*210)
    logger.info(f"[+] Geting network flow of {INTERFACE} in {DURATION} seconds.")
    error, df_metric = argus_client.get_metric(
        path_to_ra="/usr/local/bin/ra",
        server="localhost",
        port=561,
        duration_in_seconds=DURATION,
    )
    # Record End time
    end_time = datetime.datetime.now()
    capture_duration = (end_time - start_time).total_seconds()

    if error:
        logger.error(error)
    else:
        # List statistics
        total_packets = len(df_metric)
        total_bytes = 0
        if 'TotBytes' in df_metric.columns:
            total_packets = df_metric['TotBytes'].fillna(0).sum()
        lost_packets = 0
        if 'Loss' in df_metric.columns:
            lost_packets = df_metric['Loss'].fillna(0).sum()
        # display statistics
        logger.info("[+] Packet Capture Statistics [+] ")
        logger.info(f"<> Total packets captured: {total_packets}")
        logger.info(f"<> Total bytes captured: {total_bytes}")
        logger.info(f"<> Lost packest: {lost_packets}")
        logger.info(f"<> Duration: {capture_duration:.2f}")
        # Save to CSV
        timestamp = datetime.datetime.now().strftime("%d%m%Y-%H:%H:%S")
        csv_filename = f"argus_capture_{timestamp}.csv"
        df_metric.to_csv(csv_filename,index=False)
        logger.info(f"Network Traffic are saved to {csv_filename}.")
        print('-'*210)
        print("\n [+] Initial Traffic:",df_metric)
        print('-'*210)

        # One hot encoding
        df = pd.get_dummies(df_metric, columns=['Proto', 'State', 'Flgs'], prefix='', prefix_sep='', dtype=int)

        # Chỉ giữ các one-hot column cần thiết
        required_onehot = ['tcp', 'icmp', 'RST', 'REQ', 'CON', 'FIN', 'INT', ' e        ', ' e d      ']
        for col in required_onehot:
            if col not in df.columns:
                df[col] = 0

        # Tạo trường nhị phân 'Status'
        df['Status'] = df_metric['Cause'].apply(lambda x: 1 if x == 'Status' else 0)

        # Danh sách cột đầu vào cho mô hình theo thu tu
        required_columns = [
            'tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 'dMeanPktSz',
            'Offset', 'CON', 'FIN', 'sTtl', ' e        ', 'INT', 'Mean', 'Status',
            'icmp', 'SrcTCPBase', ' e d      ', 'sMeanPktSz', 'DstLoss', 'Loss',
            'dTtl', 'SrcBytes', 'TotBytes'
        ]

        # Thêm các cột còn thiếu nếu chưa có trong df
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0

        # Tạo DataFrame cuối cùng đúng thứ tự
        df_final = df[required_columns]
        print("\n Proccessed Traffic: ",df_final)
        print('-'*210)
        df_final = df_final.fillna(0)

        y_preds = rf_model.predict(df_final)
    with open('prediction_results.txt', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Sample Index', 'Time', 'Label', 'Attack Type', 'Attack Tool'])

        # Display results and write to file
        print("\nPresenting Results:")
        for idx, y_pred in enumerate(y_preds):
            try:
                label, attack_type, tool = y_pred.split('_')
            except:
                label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
            current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
            print(f"Sample {idx + 1} [{current_time}]:")
            print(f"  - Label        : {label}")
            print(f"  - Attack Type  : {attack_type}")
            print(f"  - Attack Tool  : {tool}\n")
            writer.writerow([idx + 1, current_time, label, attack_type, tool])

    if started:
        argus.kill_argus(process)
    else:
        argus.kill_argus()

    while True:
        logger.info("Stopping for the argus server ...")
        time.sleep(3)
        is_running, pid = argus.is_argus_running()
        if not is_running:
            logger.info("The argus server is stoped.")
            break