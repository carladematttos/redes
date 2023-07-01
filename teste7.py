import jwt
import socket

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
iApHCXrKq076+12Df8CfUPSrScm8HptyD6Xz1yJq6AOmr1rB5CGUHjNHwEV
lsrLw3gTlAszxGMcvNINWRQJAdGmgXJDKHziJIkWt5dTcqj7Gnm7y1r0KNxJ66iv
ENsylqBhJ3TMW4W2Eyq8AWJLoxTZtx+PrR5RQGr+keVh5qg==
-----END RSA PRIVATE KEY-----
'''


def generate_token(payload):
    encoded_token = jwt.encode(payload, private_key, algorithm='RS256')
    return encoded_token


def verify_token(encoded_token):
    try:
        decoded_token = jwt.decode(encoded_token, public_key, algorithms=['RS256'])
        return decoded_token
    except jwt.InvalidSignatureError:
        print("Assinatura inválida")
    except jwt.DecodeError:
        print("Não foi possível decodificar o token")
    return None


ip = '3.204.246.63'
portas = [2000, 23456, 34567]

payload = {
    "group": "NONAME",
    "seq_number": 1,
    "seq_max": 4,
    "matricula": 20150466,
}

encoded_token = generate_token(payload)

for porta in portas:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (ip, porta)
        sock.sendto(encoded_token, server_address)
        data, _ = sock.recvfrom(4096)
        decoded_response = verify_token(data)
        if decoded_response:
            # Processar a resposta do servidor
            print("Resposta recebida:", decoded_response)
    except Exception as e:
        print(f"Erro ao enviar para a porta {porta}: {str(e)}")
    finally:
        sock.close()
