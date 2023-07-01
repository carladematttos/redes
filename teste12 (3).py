import socket
import argparse
import jwt
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Chaves públicas e privadas
PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6WxHzHil173GFXttAF6dEIGXf
T5tSBv7l1pgX2hsIC1bVRTy4f8eiEWIing0fdXS/X2jsPMH02vFleGU+7Fvmo0fW
vSPgeOdLavydF+atLptGHNY9wsfTozhDwwgn+dw9vEgfJ9uySvcKWt/TrgX7xXSv
82siHc1X63P9D8wdgwIDAQAB
-----END PUBLIC KEY-----'''

PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'''

# Configurações do protocolo
GROUP_NAME = "NONAME"
SEQ_MAX = 4
SECRET_KEY = b'dec7557-socket-udp-with-jwt'

def create_token(payload):
    header = {"alg": "RS256"}
    encoded_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers=header)
    return encoded_token

def verify_token(token):
    try:
        decoded_token = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        return True, decoded_token
    except jwt.InvalidTokenError:
        return False, None

def create_payload(seq_number, matricula):
    payload = {
        "group": GROUP_NAME,
        "seq_number": seq_number,
        "seq_max": SEQ_MAX,
        "matricula": matricula
    }
    return payload

def send_udp_message(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))
    sock.close()

def receive_udp_message(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    data, addr = sock.recvfrom(1024)
    sock.close()
    return data.decode(), addr

def write_report(report_file, report):
    with open(report_file, "a") as file:
        file.write(report)

def main():
    parser = argparse.ArgumentParser(description="Network Connection Tester")
    parser.add_argument("ip", type=str, help="IP address to test")
    parser.add_argument("report_file", type=str, help="Path to the report file")

    args = parser.parse_args()

    ip = args.ip
    report_file = args.report_file

    ports = [2000, 23456, 34567]
    seq_numbers = [1, 2, 3, 4]
    matriculas = [20150466, 20150467, 20150468, 20150469]

    for port in ports:
        for seq_number, matricula in zip(seq_numbers, matriculas):
            payload = create_payload(seq_number, matricula)
            token = create_token(payload)

            message = token  # Use the token directly without decoding
            send_udp_message(ip, port, message)

            response, _ = receive_udp_message(port)

            is_valid, decoded_response = verify_token(response)
            if is_valid:
                id_request = SHA256.new(message.encode()).hexdigest()
                next_number = decoded_response.get("next_number")
                otp_number = decoded_response.get("otp_number")
                otp_timestamp = decoded_response.get("otp_timestamp")

                response_payload = {
                    "id_request": id_request,
                    "next_number": next_number,
                    "otp_number": otp_number,
                    "otp_timestamp": otp_timestamp
                }
                response_token = jwt.encode(response_payload, SECRET_KEY, algorithm="HS256")

                is_valid, _ = verify_token(response_token)
                result = "OK" if is_valid else "NOT_OK"

                report = f"Received Response: {response}\n"
                report += f"Signature Verification Result: {result}\n"
                report += f"Response Token: {response_token}\n"
                report += f"Response Signature: {decoded_response.get('signature')}\n"
                report += f"Response ID Request: {id_request}\n"
                report += f"Response Next Number: {next_number}\n"
                report += f"Response OTP Number: {otp_number}\n"
                report += f"Response OTP Timestamp: {otp_timestamp}\n"
                report += "-------------------------------------\n"

                write_report(report_file, report)
            else:
                report = f"Received Invalid Response: {response}\n"
                report += "-------------------------------------\n"

                write_report(report_file, report)

if __name__ == "__main__":
    main()

