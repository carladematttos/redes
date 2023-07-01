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
R6S7vYZwo5juOmABZJC20r09mGJUCydzdoMuvZuz8rMha1xMOt/aFhNG7QJAH2nu
iApHCXrKq076+12Df8CfUPSrScm8HptyD6Xz1yJq6AOmr1rB5CGUHjNHwEVlsrLw
3gTlAszxGMcvNINWRQJAdGmgXJDKHziJIkWt5dTcqj7Gnm7y1r0KNxJ66ivENsyl
qBhJ3TMW4W2Eyq8AWJLoxTZtx+PrR5RQGr+keVh5qg==
-----END RSA PRIVATE KEY-----"""

# Endereço IP e portas
ip = "3.204.246.63"
portas = [2000, 23456, 34567]

# Dados do payload
dados_payload = {
    "group": "NONAME",
    "seq_number": 1,
    "seq_max": 4
}

# Números de matrícula
matriculas = [20150466, 20150467, 20150468, 20150469]

# Criação do token JWT
def criar_token(payload):
    return jwt.encode(payload, private_key, algorithm="RS256").decode("utf-8")

# Conversão de dados para bytes
def converter_para_bytes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    elif isinstance(data, dict):
        return json.dumps(data).encode("utf-8")
    else:
        return data

# Enviar dados para o servidor remoto
def enviar_dados(ip, porta, dados):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(converter_para_bytes(dados), (ip, porta))
    print(f"Dados enviados para a porta {porta}")

# Envio dos dados para cada porta
for porta in portas:
    # Atualiza o número de matrícula no payload
    dados_payload["matricula"] = matriculas[portas.index(porta)]
    
    # Cria o token JWT com o payload atualizado
    token = criar_token(dados_payload)

    # Monta os dados para enviar ao servidor
    dados_enviar = {
        "token": token,
        "payload": dados_payload
    }

    # Envia os dados para o servidor
    enviar_dados(ip, porta, dados_enviar)
