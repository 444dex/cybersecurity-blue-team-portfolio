#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Monitora integridade de arquivos críticos e detecta modificações não autorizadas
"""

import os
import sys
import hashlib
import sqlite3
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Cria diretório de logs se não existir
Path('logs').mkdir(exist_ok=True)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('logs/fim.log'),
        logging.StreamHandler()
    ]
)


class IntegrityDatabase:
    """Gerencia baseline de integridade"""
    
    def __init__(self, db_path='baseline.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializa banco de dados"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT UNIQUE NOT NULL,
                hash_sha256 TEXT NOT NULL,
                file_size INTEGER,
                permissions TEXT,
                owner TEXT,
                modified_time REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                filepath TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                severity TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_file(self, filepath, file_hash, file_size, permissions, owner, mtime):
        """Adiciona arquivo ao baseline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO baseline 
                (filepath, hash_sha256, file_size, permissions, owner, modified_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (filepath, file_hash, file_size, permissions, owner, mtime))
            
            conn.commit()
        except Exception as e:
            logging.error(f"Erro ao adicionar arquivo ao baseline: {e}")
        finally:
            conn.close()
    
    def get_file_hash(self, filepath):
        """Obtém hash do arquivo do baseline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT hash_sha256 FROM baseline WHERE filepath = ?',
            (filepath,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    
    def log_event(self, filepath, event_type, old_hash, new_hash, severity, details=''):
        """Registra evento de integridade"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO events 
            (filepath, event_type, old_hash, new_hash, severity, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (filepath, event_type, old_hash, new_hash, severity, details))
        
        conn.commit()
        conn.close()
    
    def get_baseline_count(self):
        """Retorna número de arquivos no baseline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM baseline')
        count = cursor.fetchone()[0]
        conn.close()
        return count


class FileIntegrityMonitor:
    """Monitor de integridade de arquivos"""
    
    # Arquivos críticos do sistema
    CRITICAL_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/etc/hosts',
        '/etc/crontab'
    ]
    
    def __init__(self):
        self.db = IntegrityDatabase()
        
        # Cria diretório de logs
        os.makedirs('logs', exist_ok=True)
    
    def calculate_hash(self, filepath):
        """
        Calcula hash SHA-256 de um arquivo
        
        Args:
            filepath: Caminho do arquivo
            
        Returns:
            str: Hash SHA-256
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                # Lê em chunks para arquivos grandes
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            return sha256_hash.hexdigest()
        
        except Exception as e:
            logging.error(f"Erro ao calcular hash de {filepath}: {e}")
            return None
    
    def get_file_metadata(self, filepath):
        """
        Obtém metadados do arquivo
        
        Args:
            filepath: Caminho do arquivo
            
        Returns:
            dict: Metadados do arquivo
        """
        try:
            stat_info = os.stat(filepath)
            
            return {
                'size': stat_info.st_size,
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': stat_info.st_uid,
                'modified_time': stat_info.st_mtime
            }
        
        except Exception as e:
            logging.error(f"Erro ao obter metadados de {filepath}: {e}")
            return None
    
    def create_baseline(self, directory):
        """
        Cria baseline de integridade para um diretório
        
        Args:
            directory: Diretório a escanear
        """
        logging.info(f"Criando baseline para {directory}")
        
        file_count = 0
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                # Pula links simbólicos
                if os.path.islink(filepath):
                    continue
                
                try:
                    # Calcula hash
                    file_hash = self.calculate_hash(filepath)
                    if not file_hash:
                        continue
                    
                    # Obtém metadados
                    metadata = self.get_file_metadata(filepath)
                    if not metadata:
                        continue
                    
                    # Adiciona ao baseline
                    self.db.add_file(
                        filepath,
                        file_hash,
                        metadata['size'],
                        metadata['permissions'],
                        metadata['owner'],
                        metadata['modified_time']
                    )
                    
                    file_count += 1
                    
                    if file_count % 100 == 0:
                        logging.info(f"Processados {file_count} arquivos...")
                
                except Exception as e:
                    logging.error(f"Erro ao processar {filepath}: {e}")
                    continue
        
        logging.info(f"Baseline criado: {file_count} arquivos")
    
    def check_integrity(self, filepath):
        """
        Verifica integridade de um arquivo
        
        Args:
            filepath: Caminho do arquivo
            
        Returns:
            tuple: (status, details)
        """
        # Calcula hash atual
        current_hash = self.calculate_hash(filepath)
        if not current_hash:
            return ('error', 'Não foi possível calcular hash')
        
        # Obtém hash do baseline
        baseline_hash = self.db.get_file_hash(filepath)
        
        if baseline_hash is None:
            # Arquivo novo
            return ('new', 'Arquivo não existe no baseline')
        
        if current_hash != baseline_hash:
            # Arquivo modificado
            return ('modified', f'Hash mudou: {baseline_hash[:16]}... -> {current_hash[:16]}...')
        
        # Arquivo íntegro
        return ('ok', 'Hash corresponde ao baseline')
    
    def verify_directory(self, directory):
        """
        Verifica integridade de todos os arquivos em um diretório
        
        Args:
            directory: Diretório a verificar
        """
        logging.info(f"Verificando integridade de {directory}")
        
        modified_files = []
        new_files = []
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                if os.path.islink(filepath):
                    continue
                
                status, details = self.check_integrity(filepath)
                
                if status == 'modified':
                    modified_files.append(filepath)
                    severity = 'CRITICAL' if filepath in self.CRITICAL_FILES else 'MEDIUM'
                    
                    logging.warning(f"⚠️  MODIFICADO: {filepath}")
                    logging.warning(f"   {details}")
                    
                    # Registra evento
                    self.db.log_event(
                        filepath,
                        'MODIFIED',
                        self.db.get_file_hash(filepath),
                        self.calculate_hash(filepath),
                        severity,
                        details
                    )
                
                elif status == 'new':
                    new_files.append(filepath)
                    logging.info(f"ℹ️  NOVO: {filepath}")
        
        # Resumo
        logging.info(f"\n{'='*60}")
        logging.info("RESUMO DA VERIFICAÇÃO")
        logging.info(f"{'='*60}")
        logging.info(f"Arquivos modificados: {len(modified_files)}")
        logging.info(f"Novos arquivos: {len(new_files)}")
        
        if modified_files:
            logging.warning("\nArquivos modificados:")
            for f in modified_files:
                logging.warning(f"  - {f}")


class FileSystemMonitorHandler(FileSystemEventHandler):
    """Handler para eventos do filesystem"""
    
    def __init__(self, fim):
        self.fim = fim
        super().__init__()
    
    def on_modified(self, event):
        """Evento de arquivo modificado"""
        if event.is_directory:
            return
        
        filepath = event.src_path
        
        # Verifica integridade
        status, details = self.fim.check_integrity(filepath)
        
        if status == 'modified':
            severity = 'CRITICAL' if filepath in FileIntegrityMonitor.CRITICAL_FILES else 'MEDIUM'
            
            logging.warning(f"\n  ALERTA: Arquivo modificado em tempo real")
            logging.warning(f"  Arquivo: {filepath}")
            logging.warning(f"  Timestamp: {datetime.now()}")
            logging.warning(f"  Severidade: {severity}")
            logging.warning(f"  Detalhes: {details}")
            
            # Registra evento
            self.fim.db.log_event(
                filepath,
                'MODIFIED',
                self.fim.db.get_file_hash(filepath),
                self.fim.calculate_hash(filepath),
                severity,
                details
            )
    
    def on_created(self, event):
        """Evento de arquivo criado"""
        if event.is_directory:
            return
        
        filepath = event.src_path
        
        logging.warning(f"\n  ALERTA: Novo arquivo detectado")
        logging.warning(f"  Arquivo: {filepath}")
        logging.warning(f"  Timestamp: {datetime.now()}")
        
        # Registra evento
        file_hash = self.fim.calculate_hash(filepath)
        self.fim.db.log_event(
            filepath,
            'CREATED',
            None,
            file_hash,
            'HIGH',
            'Novo arquivo criado'
        )
    
    def on_deleted(self, event):
        """Evento de arquivo deletado"""
        if event.is_directory:
            return
        
        filepath = event.src_path
        severity = 'CRITICAL' if filepath in FileIntegrityMonitor.CRITICAL_FILES else 'MEDIUM'
        
        logging.warning(f"\n  ALERTA: Arquivo deletado")
        logging.warning(f"  Arquivo: {filepath}")
        logging.warning(f"  Timestamp: {datetime.now()}")
        logging.warning(f"  Severidade: {severity}")
        
        # Registra evento
        self.fim.db.log_event(
            filepath,
            'DELETED',
            self.fim.db.get_file_hash(filepath),
            None,
            severity,
            'Arquivo deletado'
        )


def main():
    parser = argparse.ArgumentParser(
        description='File Integrity Monitor - Monitoramento de integridade de arquivos'
    )
    
    parser.add_argument(
        '--init',
        action='store_true',
        help='Criar baseline inicial'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Verificar integridade'
    )
    parser.add_argument(
        '--monitor',
        action='store_true',
        help='Monitorar em tempo real'
    )
    parser.add_argument(
        '--path',
        action='append',
        help='Diretório(s) a monitorar'
    )
    
    args = parser.parse_args()
    
    if not args.path:
        print("Erro: Especifique pelo menos um diretório com --path")
        sys.exit(1)
    
    # Inicializa FIM
    fim = FileIntegrityMonitor()
    
    if args.init:
        # Criar baseline
        for directory in args.path:
            if os.path.isdir(directory):
                fim.create_baseline(directory)
            else:
                logging.error(f"Diretório não encontrado: {directory}")
    
    elif args.check:
        # Verificar integridade
        for directory in args.path:
            if os.path.isdir(directory):
                fim.verify_directory(directory)
            else:
                logging.error(f"Diretório não encontrado: {directory}")
    
    elif args.monitor:
        # Monitorar em tempo real
        logging.info(f"Iniciando monitoramento em tempo real")
        logging.info(f"Baseline: {fim.db.get_baseline_count()} arquivos")
        logging.info(f"Pressione Ctrl+C para parar\n")
        
        observer = Observer()
        handler = FileSystemMonitorHandler(fim)
        
        for directory in args.path:
            if os.path.isdir(directory):
                observer.schedule(handler, directory, recursive=True)
                logging.info(f"Monitorando: {directory}")
            else:
                logging.error(f"Diretório não encontrado: {directory}")
        
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            logging.info("\nMonitoramento interrompido")
        
        observer.join()
    
    else:
        print("Erro: Especifique --init, --check ou --monitor")
        sys.exit(1)


if __name__ == '__main__':
    main()
