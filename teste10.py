import socket
import argparse
import jwt
import json
import time
import hashlib
import hmac
import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----
"""


def send_udp_message(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Cria um objeto de soquete UDP
    sock.sendto(message.encode(), (ip, port))  # Envia a mensagem para o endereço IP e porta especificados
    sock.close()  # Fecha o soquete


def generate_jws_token(payload, private_key):
    headers = {
        "alg": "RS256",
        "typ": "JWT"
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)  # Gera o token JWT com a chave privada
    return token.decode()


def verify_jws_token(token, public_key):
    decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])  # Decodifica e verifica o token usando a chave pública
    return decoded_token


def get_current_timestamp():
    return int(datetime.datetime.now().timestamp())


def save_response_to_file(response, is_valid, file_path):
    with open(file_path, 'a') as file:
        file.write(f"Resposta do servidor: {response}\n")
        file.write(f"Validação da assinatura: {'OK' if is_valid else 'NOT_OK'}\n\n")


def send_request(ip, port, payload, private_key, public_key, response_file):
    token = generate_jws_token(payload, private_key)
    send_udp_message(ip, port, token)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', port))
        sock.settimeout(5)

        data, addr = sock.recvfrom(1024)  # Tenta receber dados de volta do servidor UDP
        response_token = data.decode('utf-8')  # Decodifica o token recebido

        is_valid = False
        try:
            decoded_token = verify_jws_token(response_token, public_key)  # Verifica a assinatura usando a chave pública
            is_valid = True
        except jwt.exceptions.InvalidTokenError:
            pass

        save_response_to_file(response_token, is_valid, response_file)

        if is_valid:
            response_payload = {
                "id_request": hashlib.sha256(token.encode()).hexdigest(),
                "next_number": payload["seq_number"] + 1,
                "otp_number": 3205,
                "otp_timestamp": get_current_timestamp()
            }
            response_token = generate_jws_token(response_payload, private_key)
            send_udp_message(ip, port, response_token)

    except socket.timeout:
        print("Timeout ao aguardar resposta do servidor")


def scan_udp(ip, port, private_key, public_key, response_file):
    for seq_number in range(1, 5):
        payload = {
            "group": "NONAME",
            "seq_number": seq_number,
            "seq_max": 4,
            "matricula": f"2015046{seq_number}"
        }
        send_request(ip, port, payload, private_key, public_key, response_file)


def main():
    parser = argparse.ArgumentParser(description='Envio de Dados via UDP com JWT')  # Cria um objeto de análise de argumentos
    parser.add_argument('ip', type=str, help='Endereço IP do servidor')
    parser.add_argument('port', type=int, help='Porta do servidor')
    parser.add_argument('--output', type=str, help='Arquivo de saída para salvar as respostas')

    args = parser.parse_args()

    private_key_str = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

    public_key_str = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----
"""

    private_key = serialization.load_pem_private_key(private_key_str.encode(), password=None,
                                                     backend=default_backend())
    public_key = serialization.load_pem_public_key(public_key_str.encode(), backend=default_backend())

    ip = args.ip
    port = args.port
    response_file = args.output

    if response_file is None:
        response_file = "responses.txt"

    scan_udp(ip, port, private_key, public_key, response_file)


if __name__ == '__main__':
    main()
