from argus_tool import argus_server, argus_client
import time
import logging
import datetime
import pytz
from joblib import load
import pandas as pd


APP_NAME = "ArgusTest"
INTERFACE = "ens33"
DURATION = 15

rf_model = load('rf_model.joblib')

if __name__ == "__main__":

    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    started, process = argus_server.start_argus(
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

            is_running, pid = argus_server.is_argus_server_running()
            if is_running:
                logger.info(f"The argus server is running PID = {pid}.")
                break

    logger.info(f"Geting network flow of {INTERFACE} in {DURATION} seconds.")
    error, df_metric = argus_client.get_metric(
        path_to_ra="/usr/local/bin/ra",
        server="localhost",
        port=561,
        duration_in_seconds=DURATION,
    )

    if error:
        logger.error(error)
    else:
        print(df_metric)

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
        print(df_final)

        df_final = df_final.fillna(0)

        y_preds = rf_model.predict(df_final)

        # Hiển thị kết quả
        print("\nKết quả dự đoán các mẫu:")
        for idx, y_pred in enumerate(y_preds):
            try:
                label, attack_type, tool = y_pred.split('_')
            except:
                label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
            current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
            print(f"Mẫu {idx + 1} [{current_time}]:")
            print(f"  - Label        : {label}")
            print(f"  - Attack Type  : {attack_type}")
            print(f"  - Attack Tool  : {tool}\n")

    if started:
        argus_server.kill_argus(process)
    else:
        argus_server.kill_argus()

    while True:
        logger.info("Stopping for the argus server ...")
        time.sleep(3)
        is_running, pid = argus_server.is_argus_server_running()
        if not is_running:
            logger.info("The argus server is stoped.")
            break
