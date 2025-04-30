import time
import pandas as pd
from joblib import dump
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("/home/bacan/5g_monitor/Dataset_Using.csv", low_memory=False)
df = df.drop(columns=['Unnamed: 0'], errors='ignore')

df['Multiclass_Label'] = df['Label'] + "_" + df['Attack Type'] + "_" + df['Attack Tool']
X = df.drop(columns=["Label", "Attack Type", "Attack Tool", "Multiclass_Label"])
y = df["Multiclass_Label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

for col in ['dTtl', 'SrcTCPBase', 'sTtl', 'sHops']:
    X_train.fillna({col: -1}, inplace=True)
    X_test.fillna({col: -1}, inplace=True)


# Khởi tạo mô hình
rf_model = RandomForestClassifier()

# Ghi nhận thời gian bắt đầu
start_time = time.time()

# Huấn luyện mô hình
rf_model.fit(X_train, y_train)

# Ghi nhận thời gian kết thúc
end_time = time.time()
execution_time = end_time - start_time

print(f"⏱️ Thời gian huấn luyện: {execution_time:.2f} giây")


dump(rf_model, 'rf_model.joblib')
