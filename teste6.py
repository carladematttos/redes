import socket
import argparse
import requests
import jwt
import json

# Chave secreta compartilhada para o algoritmo HS256
SECRET_KEY = "dec7557-socket-udp-with-jwt"

# Chaves públicas e privadas
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----"""

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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

def create_jwt_token(payload):
    # Gera um token JWT com o payload especificado
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return token

def verify_jwt_token(token):
    # Verifica a validade do token JWT e retorna o payload se for válido
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        return payload
    except jwt.InvalidTokenError:
        return None

def send_udp_message(ip, port, message):
    # Envia uma mensagem UDP para o endereço IP e porta especificados
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))
    sock.close()

def get_weather(city):
    # Obtém informações sobre o clima de uma cidade usando a API do OpenWeatherMap
    api_key = "your_api_key"
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        weather_description = data['weather'][0]['description']
        return weather_description
    else:
        return None

def main():
    # Parsing dos argumentos de linha de comando
    parser = argparse.ArgumentParser(description="UDP Client")
    parser.add_argument("server_ip", help="IP address of the server")
    parser.add_argument("server_port", type=int, help="port number of the server")
    parser.add_argument("city", help="name of the city")
    args = parser.parse_args()

    # Cria o payload do token JWT com os dados da cidade
    payload = {
        "city": args.city,
        "weather": get_weather(args.city)
    }

    # Cria o token JWT
    token = create_jwt_token(payload)

    # Envia a mensagem UDP com o token JWT para o servidor
    send_udp_message(args.server_ip, args.server_port, token)

if __name__ == "__main__":
    main()
