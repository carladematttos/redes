import socket
import argparse
import json
import jwt
import time

# Chaves pública e privada fornecidas
PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----
"""

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
3gTlAszxGMcvNINWRQJBAKk7HjJUjke+QL6Z5jTFxIqlHeE7Y9kqzlsMg5Tq4xBg
KZvxlEeJ6CVYMn71g7K4/3zOrtXz8hF7qBQXf4+85Eo=
-----END RSA PRIVATE KEY-----
"""

# Dados de conexão
SERVER_IP = "43.204.246.63"
SERVER_PORTS = [2000, 23456, 34567]

# Payload inicial
payload = {
    "group": "NONAME",
    "seq_number": 1,
    "seq_max": 4,
    "matricula": 20150466
}

def send_udp_message(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))
    sock.close()

def generate_jwt_token(payload):
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode()

def verify_jwt_token(token):
    try:
        jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        return True
    except jwt.InvalidSignatureError:
        return False

def create_payload(seq_number, seq_max, matricula):
    return {
        "group": "NONAME",
        "seq_number": seq_number,
        "seq_max": seq_max,
        "matricula": matricula
    }

def main():
    parser = argparse.ArgumentParser(description="UDP Connection Tester")
    parser.add_argument("ip", type=str, help="IP address to test")

    args = parser.parse_args()
    ip = args.ip

    # Realizar os 4 envios
    for i in range(1, 5):
        # Criar o payload com o número de matrícula atual
        payload = create_payload(i, 4, 20150465 + i)
        
        # Gerar o token JWT
        token = generate_jwt_token(payload)
        
        # Enviar o token como mensagem UDP para o servidor em cada porta
        for port in SERVER_PORTS:
            send_udp_message(SERVER_IP, port, token)
        
        # Aguardar um tempo para receber a resposta
        time.sleep(1)
        
        # Receber e verificar a resposta do servidor em cada porta
        for port in SERVER_PORTS:
            response = receive_udp_message(ip, port)
            is_valid = verify_jwt_token(response)
            
            # Salvar a resposta em um arquivo
            with open("resposta.txt", "a") as file:
                file.write(f"Resposta {i} (Porta {port}):\n")
                file.write(f"Token: {response}\n")
                file.write(f"Assinatura válida: {is_valid}\n\n")

if __name__ == "__main__":
    main()
