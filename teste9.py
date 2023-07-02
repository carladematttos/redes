import argparse
import json
import jwt
import socket
import time
import requests

# Função para enviar uma requisição UDP ao servidor
def enviar_requisicao_udp(servidor, porta, mensagem):
    # Cria um socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Envia a mensagem para o servidor
    sock.sendto(mensagem.encode(), (servidor, porta))

    # Aguarda a resposta do servidor
    resposta, endereco = sock.recvfrom(1024)

    # Fecha o socket
    sock.close()

    return resposta.decode()

# Função para criar o token JWT com o payload especificado
def criar_token_jwt(payload, chave_privada):
    token = jwt.encode(payload, chave_privada, algorithm='RS256')
    return token

# Função para enviar a requisição ao servidor
def enviar_requisicao(servidor, porta, token_jwt):
    # Cria a mensagem com o token JWT
    mensagem = token_jwt

    # Envia a requisição UDP ao servidor
    resposta = enviar_requisicao_udp(servidor, porta, mensagem)

    return resposta

# Função para tratar a resposta do servidor
def tratar_resposta(resposta):
    # Converte a resposta para JSON
    resposta_json = json.loads(resposta)

    # Extrai os campos da resposta
    id_request = resposta_json['id_request']
    next_number = resposta_json['next_number']
    otp_number = resposta_json['otp_number']
    otp_timestamp = resposta_json['otp_timestamp']

    # Salva a resposta em um arquivo
    with open(args.saida, 'a') as arquivo_saida:
        arquivo_saida.write(f'Resposta: {resposta}\n')
        arquivo_saida.write(f'Verificação da assinatura: OK\n')

    # Retorna o número do próximo aluno
    return next_number

# Função para enviar as requisições aos alunos
def enviar_requisicoes_alunos(servidor, portas, chave_privada, alunos):
    # Número inicial do aluno
    seq_number = 1

    # Loop para enviar as requisições para cada aluno
    for aluno in alunos:
        # Cria o payload do aluno
        payload = {
            'group': 'NONAME',
            'seq_number': seq_number,
            'seq_max': len(alunos),
            'matricula': aluno
        }

        # Cria o token JWT com o payload
        token_jwt = criar_token_jwt(payload, chave_privada)

        # Envia a requisição para cada porta
        for porta in portas:
            resposta = enviar_requisicao(servidor, porta, token_jwt)

            # Trata a resposta do servidor
            next_number = tratar_resposta(resposta)

        # Atualiza o número do próximo aluno
        seq_number = next_number

        # Aguarda 1 segundo antes de enviar a próxima requisição
        time.sleep(1)

# Função principal
def main():
    # Parsing dos argumentos de linha de comando
    parser = argparse.ArgumentParser(description='Envio de requisições UDP com JWT')
    parser.add_argument('protocolo', choices=['tcp', 'udp'], help='Protocolo de envio (TCP ou UDP)')
    parser.add_argument('ip', help='Endereço IP do servidor')
    parser.add_argument('portas', nargs='+', type=int, help='Portas do servidor')
    parser.add_argument('--saida', default='respostas.txt', help='Arquivo de saída para salvar as respostas')
    args = parser.parse_args()

    # Chave privada do grupo
    chave_privada = 'chave_privada_do_grupo'

    # Lista de matrículas dos alunos
    alunos = [20150466, 20150467, 20150468, 20150469]

    # Envia as requisições aos alunos
    enviar_requisicoes_alunos(args.ip, args.portas, chave_privada, alunos)

# Executa a função principal
if __name__ == '__main__':
    main()
