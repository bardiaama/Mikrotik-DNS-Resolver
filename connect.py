import paramiko

HOST = "46.100.26.176"
PORT = 6480
USERNAME = "user1"
PASSWORD = "qwert"


def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=10)
    return client


def run(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return out or err


if __name__ == "__main__":
    client = connect()
    print("Connected to", HOST)
    print(run(client, "/system identity print"))
    client.close()
