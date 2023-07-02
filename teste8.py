import socket
import argparse
import requests
from datetime import datetime
import jwt
import hashlib

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

SECRET_KEY = b'dec7557-socket-udp-with-jwt'

def send_data(ip, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload.encode('utf-8'), (ip, port))
    sock.close()

def create_token(payload):
    private_key = PRIVATE_KEY.strip()
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

def verify_token(token):
    public_key = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
    T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
    vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
    82siHc1X63P9D8wdgwIDAQAB
    -----END PUBLIC KEY-----
    """
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        return decoded_token
    except jwt.exceptions.InvalidSignatureError:
        print("Invalid token signature.")
    except jwt.exceptions.DecodeError:
        print("Error decoding token.")

def main():
    parser = argparse.ArgumentParser(description='Scanner de Rede')
    parser.add_argument('protocolo', choices=['tcp', 'udp'], help='Tipo de protocolo de transporte (TCP ou UDP)')
    parser.add_argument('ip', help='Endereço IPv4 do host de destino')
    parser.add_argument('portas', nargs='+', type=int, help='Portas a serem verificadas (separadas por vírgula)')
    parser.add_argument('--saida', '-o', help='Arquivo de saída')
    args = parser.parse_args()

    if args.protocolo == 'tcp':
        scan_tcp(args.ip, args.portas, args.saida)
    elif args.protocolo == 'udp':
        scan_udp(args.ip, args.portas, args.saida)

    ip = socket.gethostbyname(socket.gethostname())
    print("Endereço IP local:", ip)

    response = requests.get("https://api.ipify.org?format=json")
    public_ip = response.json()["ip"]
    print("Endereço IP público:", public_ip)

    seq_numbers = [1, 2, 3, 4]
    next_number = 2
    otp_number = 3205
    otp_timestamp = int(datetime.now().timestamp())

    for seq_number, matricula in zip(seq_numbers, [20150466, 20150467, 20150468, 20150469]):
        payload = {
            'group': 'NONAME',
            'seq_number': seq_number,
            'seq_max': len(seq_numbers),
            'matricula': matricula,
        }

        token = create_token(payload)
        send_data(args.ip, 34567, token)

        # Verificar resposta do servidor
        # ...
        # Receber resposta do servidor
        response_data = 'Your response data here'
        verified_token = verify_token(response_data)
        if verified_token:
            print("Token verified:", verified_token)

        id_request = hashlib.sha256(response_data.encode('utf-8')).hexdigest()
        response_payload = {
            'id_request': id_request,
            'next_number': next_number,
            'otp_number': otp_number,
            'otp_timestamp': otp_timestamp,
        }
        response_token = jwt.encode(response_payload, SECRET_KEY, algorithm='HS256')

        # Salvar resposta em arquivo
        # ...
        # Enviar mensagem do próximo aluno
        send_data(args.ip, 34567, response_token)

        next_number += 1

if __name__ == '__main__':
    main()
