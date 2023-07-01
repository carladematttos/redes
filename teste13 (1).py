import socket
import json
import jwt
import hashlib
import time

# Chaves públicas e privadas
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

# Payload padrão para enviar
payload_template = {
    "group": "NONAME",
    "seq_number": 1,
    "seq_max": 4,
    "matricula": 0,
}

# Chave secreta para assinatura da resposta
SECRET_KEY = b"dec7557-socket-udp-with-jwt"

def sign_payload(payload):
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return token

def send_udp_data_with_jwt(ip, port, matricula):
    # Monta o payload com a matrícula atualizada
    payload = payload_template.copy()
    payload["matricula"] = matricula

    # Gera o token JWS
    token = sign_payload(payload)

    # Monta a mensagem UDP
    message = {
        "jwt": token,
    }
    message_json = json.dumps(message).encode()

    # Envia a mensagem UDP para o servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message_json, (ip, port))

    # Aguarda a resposta do servidor
    data, addr = sock.recvfrom(1024)
    response = json.loads(data.decode())

    # Verifica a assinatura do token de resposta
    try:
        jwt.decode(response["jwt"], SECRET_KEY, algorithms=["HS256"])
        signature_verification = "OK"
    except jwt.InvalidSignatureError:
        signature_verification = "NOT_OK"

    # Salva a resposta bruta e a verificação da assinatura em um arquivo
    with open("resposta.txt", "a") as file:
        file.write(f"Resposta bruta: {data.decode()}\n")
        file.write(f"Verificação da assinatura: {signature_verification}\n\n")

    # Fecha o socket
    sock.close()

    # Retorna a resposta recebida
    return response


# Exemplo de uso
ip = "43.204.246.63"
ports = [2000, 23456, 34567]

for i in range(4):
    matricula = 20150466 + i
    response = send_udp_data_with_jwt(ip, ports[0], matricula)
    print("Resposta:", response)
    print("----------------------------------")
    time.sleep(1)  # Aguarda 1 segundo antes de enviar a próxima mensagem
