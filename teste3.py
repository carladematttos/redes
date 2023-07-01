import socket
import jwt

# Chaves públicas e privadas fornecidas
public_key = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----
"""

private_key = """
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
iApHCXrKq076+12Df8CfUPSrScm8HptyD6Xz1yJq6AOmr1rB5CGUHjNHwEVls
rQDGnLzIQ/BO0SvrrQJBAJ1xXdj6vwmFOWuZtflW9HKY8rT1gO2kM2nRX+1/Ny8C
hlHjAfGLlxzrZlqpwDeuMSOZpqOb9OszapXFcQFwhRc=
-----END RSA PRIVATE KEY-----
"""

# Endereço e portas do servidor
server_address = '43.204.246.63'
server_ports = [2000, 23456, 34567]

# Dados do payload
group_name = "NONAME"
sequence_number = 1
sequence_max = 4
matriculas = [20150466, 20150467, 20150468, 20150469]

# Criação e envio das mensagens
for matricula in matriculas:
    payload = {
        "group": group_name,
        "seq_number": sequence_number,
        "seq_max": sequence_max,
        "matricula": matricula
    }

    # Criação do token JWT assinado com a chave privada
    token = jwt.encode(payload, private_key, algorithm='RS256')

    # Criação do socket UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Envio da mensagem para cada porta do servidor
        for server_port in server_ports:
            client_socket.sendto(token.encode(), (server_address, server_port))
            print(f"Mensagem enviada para matrícula {matricula} na porta {server_port}")

            # Recebimento da resposta do servidor
            response, server = client_socket.recvfrom(4096)
            print(f"Resposta recebida do servidor na porta {server_port}: {response.decode()}")

    finally:
        # Fechamento do socket UDP
        client_socket.close()

    sequence_number += 1
