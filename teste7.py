import socket
import json
import jwt
from cryptography.hazmat.primitives import serialization

# Chaves públicas e privadas
public_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----"""

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC6WxHzHil173GFXttAF6dEIGXfT5tSBv7l1pgX2hsIC1bVRTy4
f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fWvSPgeOdLavydF+atLptGHNY9
wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv82siHc1X63P9D8wdgwIDAQAB
AoGAOS/8VKajY4ksxZhj4QnBL0Nf78T+rY/vBfoyJ1Orqu7L4VvDc/zmduItwuDM
tyQ0xQuS57gHb0wG+zQUodgnpRtGa7I8IFwdBTA7dBdPssvSGfLH0XZy/3EWuWwE
H+TCFtI5WJqFEEGVIO1BRC9lz7uodf/GxmzkcUMUmSU1fsUCQQDvQfVBPJsBFcrx
boXY0b6gwJGYNjV7zFE7mWJe356qDSyRBrftwpk6ZjM50OIbL7wFBkru1b34Zo/n
1txHkMLXAkEAx2Vugcr3lrg5ebS7Zy5P6xOjgdjIGbZPM3ybfJdUv6pcpEzUaXXt
YHYGycKbvvfw7XHrJagORh3mNQRWrEiRNQJAJyShXVTu/xRzqWAtobVe/KnEqCRm
R6S7vYZwo5juOmABZJC20r09mGJUCydzdoMuvZuz8rMha1xMOt/aFhNG7QJAH"""

# Dados para envio
data = {
    "group": "NONAME",
    "seq_number": 1,
    "seq_max": 4,
    "matricula": 20150466
}

# Convertendo os dados para JSON
payload = json.dumps(data)

# Assinando o JWT
encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256')

# Criando o socket e enviando os dados
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 2000))
    sock.sendall(encoded_jwt)
    sock.close()
    print("Dados enviados para a porta 2000 com sucesso!")
except Exception as e:
    print("Erro ao enviar para a porta 2000:", str(e))

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 23456))
    sock.sendall(encoded_jwt)
    sock.close()
    print("Dados enviados para a porta 23456 com sucesso!")
except Exception as e:
    print("Erro ao enviar para a porta 23456:", str(e))

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 34567))
    sock.sendall(encoded_jwt)
    sock.close()
    print("Dados enviados para a porta 34567 com sucesso!")
except Exception as e:
    print("Erro ao enviar para a porta 34567:", str(e))
