#!/usr/bin/env python3
"""
SSH Honeypot - Detecta e registra tentativas de ataque SSH
AVISO: Execute em ambiente controlado!
"""

import socket
import threading
import logging
import argparse
import sqlite3
from datetime import datetime
import paramiko
import sys


# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler()
    ]
)


class HoneypotDatabase:
    """Gerencia banco de dados do honeypot"""
    
    def __init__(self, db_path='honeypot.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializa tabelas do banco de dados"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela de tentativas de login
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                username TEXT,
                password TEXT,
                success INTEGER DEFAULT 0,
                country TEXT,
                city TEXT
            )
        ''')
        
        # Tabela de sessões
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                source_ip TEXT NOT NULL,
                username TEXT,
                duration INTEGER
            )
        ''')
        
        # Tabela de comandos executados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_id INTEGER,
                source_ip TEXT,
                command TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_login_attempt(self, source_ip, source_port, username, password, success=False):
        """Registra tentativa de login"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO login_attempts 
            (source_ip, source_port, username, password, success)
            VALUES (?, ?, ?, ?, ?)
        ''', (source_ip, source_port, username, password, int(success)))
        
        conn.commit()
        conn.close()
    
    def create_session(self, source_ip, username):
        """Cria nova sessão"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (source_ip, username)
            VALUES (?, ?)
        ''', (source_ip, username))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return session_id
    
    def end_session(self, session_id, duration):
        """Finaliza sessão"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions 
            SET end_time = CURRENT_TIMESTAMP, duration = ?
            WHERE id = ?
        ''', (duration, session_id))
        
        conn.commit()
        conn.close()
    
    def log_command(self, session_id, source_ip, command):
        """Registra comando executado"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO commands (session_id, source_ip, command)
            VALUES (?, ?, ?)
        ''', (session_id, source_ip, command))
        
        conn.commit()
        conn.close()


class FakeShell:
    """Shell falso que emula sistema Linux"""
    
    def __init__(self, db, session_id, source_ip):
        self.db = db
        self.session_id = session_id
        self.source_ip = source_ip
        self.cwd = '/root'
        
        # Comandos e respostas simuladas
        self.commands = {
            'whoami': 'root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
            'pwd': lambda: self.cwd,
            'uname -a': 'Linux honeypot 5.10.0-20-amd64 #1 SMP Debian x86_64 GNU/Linux',
            'cat /etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:108:113:MySQL Server,,,:/nonexistent:/bin/false''',
            'ls': 'Desktop  Documents  Downloads  Pictures  Videos',
            'ls -la': '''total 48
drwxr-xr-x 6 root root 4096 Jan 30 14:23 .
drwxr-xr-x 3 root root 4096 Jan 15 09:12 ..
-rw------- 1 root root  220 Jan 15 09:12 .bash_history
drwxr-xr-x 2 root root 4096 Jan 20 10:30 Desktop
drwxr-xr-x 2 root root 4096 Jan 20 10:30 Documents''',
            'ip addr': '''1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0''',
        }
    
    def execute(self, command):
        """
        Executa comando no shell falso
        
        Args:
            command: Comando a executar
            
        Returns:
            str: Output do comando
        """
        # Registra comando
        self.db.log_command(self.session_id, self.source_ip, command)
        logging.warning(f"Comando executado por {self.source_ip}: {command}")
        
        command = command.strip()
        
        # Detecta comandos suspeitos/maliciosos
        suspicious = ['wget', 'curl', 'nc', 'netcat', '/bin/bash', 
                     'chmod +x', './']
        
        if any(cmd in command.lower() for cmd in suspicious):
            logging.critical(f"⚠️  COMANDO SUSPEITO de {self.source_ip}: {command}")
        
        # Retorna resposta simulada
        if command in self.commands:
            response = self.commands[command]
            return response() if callable(response) else response
        
        elif command.startswith('cd '):
            path = command[3:].strip()
            self.cwd = path if path.startswith('/') else f"{self.cwd}/{path}"
            return ''
        
        elif command == 'exit':
            return None
        
        else:
            return f"-bash: {command.split()[0]}: command not found"


class SSHServerHandler(paramiko.ServerInterface):
    """Handler para servidor SSH"""
    
    def __init__(self, db, client_ip):
        self.db = db
        self.client_ip = client_ip
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        """Verifica autenticação (sempre aceita)"""
        # Registra tentativa
        self.db.log_login_attempt(
            self.client_ip,
            0,
            username,
            password,
            success=True
        )
        
        logging.info(f"Login: {username}:{password} de {self.client_ip}")
        
        # Sempre aceita (honeypot)
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind, chanid):
        """Permite requisições de canal"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        """Permite requisição PTY"""
        return True
    
    def check_channel_shell_request(self, channel):
        """Permite requisição de shell"""
        self.event.set()
        return True


class SSHHoneypot:
    """Servidor SSH Honeypot"""
    
    def __init__(self, host='0.0.0.0', port=2222, key_file='honeypot_key'):
        self.host = host
        self.port = port
        self.key = paramiko.RSAKey(filename=key_file)
        self.db = HoneypotDatabase()
    
    def handle_client(self, client_socket, client_addr):
        """
        Manipula conexão de cliente
        
        Args:
            client_socket: Socket do cliente
            client_addr: Endereço do cliente
        """
        client_ip = client_addr[0]
        logging.info(f"Nova conexão de {client_ip}:{client_addr[1]}")
        
        try:
            # Inicia sessão SSH
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.key)
            
            server = SSHServerHandler(self.db, client_ip)
            transport.start_server(server=server)
            
            # Aguarda canal
            channel = transport.accept(20)
            if channel is None:
                logging.warning(f"Cliente {client_ip} não abriu canal")
                return
            
            # Aguarda shell request
            server.event.wait(10)
            if not server.event.is_set():
                logging.warning(f"Cliente {client_ip} não requisitou shell")
                channel.close()
                return
            
            # Cria sessão
            session_start = datetime.now()
            session_id = self.db.create_session(client_ip, 'root')
            
            # Inicia shell falso
            shell = FakeShell(self.db, session_id, client_ip)
            
            channel.send(b'Welcome to Ubuntu 20.04.5 LTS\r\n')
            channel.send(b'root@honeypot:~# ')
            
            command_buffer = ''
            
            while True:
                if channel.recv_ready():
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    
                    if not data:
                        break
                    
                    # Processa entrada
                    for char in data:
                        if char == '\r' or char == '\n':
                            if command_buffer.strip():
                                # Executa comando
                                output = shell.execute(command_buffer)
                                
                                if output is None:  # exit
                                    channel.close()
                                    break
                                
                                if output:
                                    channel.send((output + '\r\n').encode())
                                
                                command_buffer = ''
                                channel.send(b'root@honeypot:~# ')
                        
                        elif char == '\x7f':  # Backspace
                            if command_buffer:
                                command_buffer = command_buffer[:-1]
                                channel.send(b'\x08 \x08')
                        
                        else:
                            command_buffer += char
                            channel.send(char.encode())
            
            # Finaliza sessão
            session_end = datetime.now()
            duration = (session_end - session_start).seconds
            self.db.end_session(session_id, duration)
            
            logging.info(f"Sessão encerrada: {client_ip} (duração: {duration}s)")
        
        except Exception as e:
            logging.error(f"Erro ao manipular cliente {client_ip}: {e}")
        
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Inicia servidor honeypot"""
        logging.info(f"SSH Honeypot iniciado em {self.host}:{self.port}")
        logging.info("Pressione Ctrl+C para parar")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)
        
        try:
            while True:
                client_socket, client_addr = server_socket.accept()
                
                # Cria thread para cada cliente
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
        
        except KeyboardInterrupt:
            logging.info("\nHoneypot interrompido pelo usuário")
        
        finally:
            server_socket.close()


def main():
    parser = argparse.ArgumentParser(description='SSH Honeypot')
    parser.add_argument('--host', default='0.0.0.0', help='Host a escutar')
    parser.add_argument('--port', type=int, default=2222, help='Porta SSH')
    parser.add_argument('--key', default='honeypot_key', help='Arquivo de chave SSH')
    
    args = parser.parse_args()
    
    # Verifica se chave existe
    try:
        paramiko.RSAKey(filename=args.key)
    except FileNotFoundError:
        print(f"Chave SSH não encontrada: {args.key}")
        print("Execute: ssh-keygen -t rsa -f honeypot_key -N \"\"")
        sys.exit(1)
    
    # Inicia honeypot
    honeypot = SSHHoneypot(args.host, args.port, args.key)
    honeypot.start()


if __name__ == '__main__':
    main()
