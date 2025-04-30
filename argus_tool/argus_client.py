import subprocess
from io import StringIO
import pandas as pd


def get_metric(
        path_to_ra: str = "/usr/local/bin/ra",
        server: str = "localhost",
        port: int = 561,
        duration_in_seconds: int = 15):
    # cmd = [
    #     path_to_ra,
    #     '-S', f'{server}:{port}',
    #     '-T', f'{duration_in_seconds}',
    #     '-c', ',',
    #     '-s',
    #     'srcid', 'stime', 'ltime', 'sstime', 'dstime', 'sltime', 'dltime',
    #     'trans', 'seq', 'flgs', 'dur', 'avgdur', 'stddev', 'mindur', 'maxdur',
    #     'saddr', 'daddr', 'proto', 'sport', 'dport', 'stos', 'dtos', 'sdsb', 'ddsb',
    #     'sco', 'dco', 'sttl', 'dttl', 'sipid', 'dipid', 'smpls', 'dmpls', 'svlan', 'dvlan',
    #     'svid', 'dvid', 'svpri', 'dvpri', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'sappbytes',
    #     'dappbytes', 'sload', 'dload', 'sloss', 'dloss', 'sploss', 'dploss', 'srate', 'drate',
    #     'smac', 'dmac', 'dir', 'sintpkt', 'dintpkt', 'sjit', 'djit', 'state', 'suser', 'duser',
    #     'swin', 'dwin', 'trans', 'srng', 'erng', 'stcpb', 'dtcpb', 'tcprtt', 'inode', 'offset',
    #     'smaxsz', 'dmaxsz', 'sminsz', 'dminsz', 'ackdat', 'shops', 'mean', 'spktsz', 'dpktsz',
    #     'cause', 'loss', 'bytes'
    # ]
    cmd = [
        path_to_ra,
        '-S', f'{server}:{port}',
        '-T', f'{duration_in_seconds}',
        '-c', ',',
        '-s',
        'proto', 'ackdat', 'shops', 'seq', 'state', 'tcprtt', 'dmeansz', 'offset', 'sttl',
        'flgs', 'mean', 'cause', 'stcpb', 'smeansz', 'dloss', 'loss', 'dttl', 'sbytes', 'bytes'
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True)
        csv_data = StringIO(result.stdout) # StringIO biến một chuỗi (str) thành file-like object (giả như file).
        df = pd.read_csv(csv_data, delimiter=',') # Đọc nội dung CSV từ csv_data (chuỗi giả file đó) thành DataFrame (df).
        return None, df
    except subprocess.CalledProcessError as e:
        return f"Failed to execute command: {e}", None
    except pd.errors.ParserError as e:
        return f"Failed to parse CSV data: {e}", None
    except Exception as e:
        return f"Unexpected error: {e}", None


