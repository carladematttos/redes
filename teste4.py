import socket
import argparse
import jwt
import json
import time

# Chaves pública e privada
public_key = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----
'''

private_key = '''
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
'''

# Dados do servidor
server_ip = "43.204.246.63"
server_ports = [2000, 23456, 34567]

# Função para enviar a requisição UDP com o token JWT
def send_udp_request(ip, port, token):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(token.encode(), (ip, port))
    sock.close()

# Função para criar o token JWT com base nos dados do payload
def create_jwt(payload):
    encoded = jwt.encode(payload, private_key, algorithm='RS256')
    return encoded.decode()

# Função para verificar a resposta JWT recebida do servidor
def verify_response_jwt(response_jwt):
    try:
        decoded = jwt.decode(response_jwt, public_key, algorithms=['RS256'])
        return True, decoded
    except jwt.InvalidSignatureError:
        return False, None

# Função principal
def main(group_name, seq_max, report_file):
    seq_number = 1
    while seq_number <= seq_max:
        # Criar o payload para a requisição
        payload = {
            "group": group_name,
            "seq_number": seq_number,
            "seq_max": seq_max,
            "matricula": 20150465 + seq_number
        }

        # Criar o token JWT
        token = create_jwt(payload)

        # Enviar a requisição UDP com o token JWT para todas as portas do servidor
        for port in server_ports:
            send_udp_request(server_ip, port, token)

        # Esperar um tempo para receber a resposta
        time.sleep(1)

        # Receber a resposta do servidor
        response, _ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM).recvfrom(1024)

        # Verificar a resposta JWT
        is_valid, decoded_response = verify_response_jwt(response.decode())

        # Salvar a resposta no arquivo de relatório
        with open(report_file, "a") as file:
            file.write(f"Response: {response.decode()}\n")
            file.write(f"Signature Verification: {'OK' if is_valid else 'NOT_OK'}\n\n")

        # Se a resposta for válida, enviar a próxima mensagem
        if is_valid:
            next_number = decoded_response["next_number"]
            if next_number > seq_number:
                seq_number = next_number
            else:
                seq_number += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Client")
    parser.add_argument("group_name", type=str, help="Name of the group")
    parser.add_argument("seq_max", type=int, help="Number of components in the group")
    parser.add_argument("report_file", type=str, help="Path to the report file")
    args = parser.parse_args()

    group_name = args.group_name.upper()
    seq_max = args.seq_max
    report_file = args.report_file

    main(group_name, seq_max, report_file)
