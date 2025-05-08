from argus_tool import argus, argus_client
import time
import logging
import datetime
import pytz
from joblib import load
import pandas as pd
import os
import csv
import argparse

# Thiết lập argparse để nhận tham số từ dòng lệnh
def parse_arguments():
    parser = argparse.ArgumentParser(description="Network traffic capture and analysis tool.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture traffic (e.g., eth0, lo)")
    parser.add_argument("-t", "--time", type=int, required=True, help="Duration of capture in seconds")
    return parser.parse_args()

APP_NAME = "ArgusTest"
if __name__ == "__main__":
    # Lấy tham số từ dòng lệnh
    args = parse_arguments()
    INTERFACE = args.interface
    DURATION = args.time

    # Tải mô hình Random Forest
    rf_model = load('my_rf_model.joblib')

    # Thiết lập logging
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Khởi động Argus server
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

    # Ghi lại thời gian bắt đầu
    start_time = datetime.datetime.now()
    print('-' * 210)
    logger.info(f"[+] Getting network flow of {INTERFACE} in {DURATION} seconds.")

    # Lấy dữ liệu mạng
    error, df_metric = argus_client.get_metric(
        path_to_ra="/usr/local/bin/ra",
        server="localhost",
        port=561,
        duration_in_seconds=DURATION,
    )

    # Ghi lại thời gian kết thúc
    end_time = datetime.datetime.now()
    capture_duration = (end_time - start_time).total_seconds()

    if error:
        logger.error(error)
    else:
        # Tính toán thống kê
        total_packets = len(df_metric)
        total_bytes = 0
        if 'TotBytes' in df_metric.columns:
            total_bytes = df_metric['TotBytes'].fillna(0).sum()
        lost_packets = 0
        if 'Loss' in df_metric.columns:
            lost_packets = df_metric['Loss'].fillna(0).sum()

        # Hiển thị thống kê
        logger.info("[+] Packet Capture Statistics [+] ")
        logger.info(f"<> Total packets captured: {total_packets}")
        logger.info(f"<> Total bytes captured: {total_bytes}")
        logger.info(f"<> Lost packets: {lost_packets}")
        logger.info(f"<> Duration: {capture_duration:.2f}")

        # Lưu vào CSV
        timestamp = datetime.datetime.now().strftime("%d%m%Y-%H:%M:%S")
        csv_filename = f"argus_capture_{timestamp}.csv"
        logger.info(f" [+] Network Traffic saved to {csv_filename}.")
        print('-' * 210)
        print(" [+] Initial Traffic: ")
        print(df_metric)
        print('-' * 210)

        # One-hot encoding
        df = pd.get_dummies(df_metric, columns=['Proto', 'State', 'Flgs'], prefix='', prefix_sep='', dtype=int)

        # Chỉ giữ các one-hot column cần thiết
        required_onehot = ['tcp', 'icmp', 'RST', 'REQ', 'CON', 'FIN', 'INT', ' e        ', ' e d      ']
        for col in required_onehot:
            if col not in df.columns:
                df[col] = 0

        # Tạo trường nhị phân 'Status'
        df['Status'] = df_metric['Cause'].apply(lambda x: 1 if x == 'Status' else 0)

        # Danh sách cột đầu vào cho mô hình theo thứ tự
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
        print("[+] Proccessed Traffic: ")
        print(df_final)
        print("-"*210)
        # Điền giá trị NaN bằng 0
        df_final = df_final.fillna(0)
        df_final.to_csv(csv_filename, index=False)
        # Dự đoán với mô hình
        y_preds = rf_model.predict(df_final)

        # Lưu kết quả dự đoán vào CSV
        with open('prediction_results.txt', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Sample Index', 'Time', 'Label', 'Attack Type', 'Attack Tool'])
            print("\nPresenting Results:")
            for idx, y_pred in enumerate(y_preds):
                try:
                    label, attack_type, tool = y_pred.split('_')
                except:
                    label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
                current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
                print("="*50)
                print(f"Sample {idx + 1} [{current_time}]:")
                print(f"  - Label        : {label}")
                print(f"  - Attack Type  : {attack_type}")
                print(f"  - Attack Tool  : {tool}\n")
                writer.writerow([idx + 1, current_time, label, attack_type, tool])

    # Dừng Argus server
    if started:
        argus.kill_argus(process)
    else:
        argus.kill_argus()

    while True:
        logger.info("Stopping the argus server ...")
        time.sleep(3)
        is_running, pid = argus.is_argus_running()
        if not is_running:
            logger.info("The argus server is stopped.")
            break