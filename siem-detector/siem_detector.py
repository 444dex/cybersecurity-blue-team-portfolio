#!/usr/bin/env python3
"""
SIEM Detector - Sistema de Detecção de Intrusão
Analisa logs de sistema e detecta atividades suspeitas
"""

import re
import json
import sqlite3
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import argparse


class SIEMDetector:
    def __init__(self, db_path="siem_alerts.db"):
        self.db_path = db_path
        self.init_database()
        self.rules = self.load_detection_rules()
        self.alert_count = defaultdict(int)
        
    def init_database(self):
        """Inicializa banco de dados para armazenar alertas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                severity TEXT,
                rule_name TEXT,
                source_ip TEXT,
                description TEXT,
                log_entry TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def load_detection_rules(self):
        """Define regras de detecção de ameaças"""
        return {
            'brute_force_ssh': {
                'pattern': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                'threshold': 5,
                'severity': 'HIGH',
                'description': 'Tentativa de força bruta SSH detectada'
            },
            'sql_injection': {
                'pattern': r"(\bUNION\b.*\bSELECT\b|\bOR\b.*=.*|'.*--)",
                'threshold': 1,
                'severity': 'CRITICAL',
                'description': 'Possível tentativa de SQL Injection'
            },
            'port_scan': {
                'pattern': r'SYN.*from (\d+\.\d+\.\d+\.\d+).*to.*(\d+)/tcp',
                'threshold': 10,
                'severity': 'MEDIUM',
                'description': 'Possível port scan detectado'
            },
            'privilege_escalation': {
                'pattern': r'(sudo|su).*COMMAND=.*(/bin/bash|/bin/sh)',
                'threshold': 1,
                'severity': 'HIGH',
                'description': 'Tentativa de escalação de privilégios'
            },
            'directory_traversal': {
                'pattern': r'\.\./|\.\.\%2F|\.\.\\',
                'threshold': 1,
                'severity': 'HIGH',
                'description': 'Tentativa de directory traversal'
            },
            'unauthorized_access': {
                'pattern': r'(403|401).*GET|POST',
                'threshold': 15,
                'severity': 'MEDIUM',
                'description': 'Múltiplas tentativas de acesso não autorizado'
            }
        }
    
    def analyze_log_line(self, line):
        """Analisa uma linha de log contra as regras de detecção"""
        alerts = []
        
        for rule_name, rule in self.rules.items():
            match = re.search(rule['pattern'], line, re.IGNORECASE)
            if match:
                source_ip = match.group(1) if match.groups() else 'Unknown'
                self.alert_count[f"{rule_name}_{source_ip}"] += 1
                
                if self.alert_count[f"{rule_name}_{source_ip}"] >= rule['threshold']:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'severity': rule['severity'],
                        'rule_name': rule_name,
                        'source_ip': source_ip,
                        'description': rule['description'],
                        'log_entry': line.strip(),
                        'count': self.alert_count[f"{rule_name}_{source_ip}"]
                    }
                    alerts.append(alert)
                    
        return alerts
    
    def save_alert(self, alert):
        """Salva alerta no banco de dados"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, severity, rule_name, source_ip, description, log_entry)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'],
            alert['severity'],
            alert['rule_name'],
            alert['source_ip'],
            alert['description'],
            alert['log_entry']
        ))
        conn.commit()
        conn.close()
    
    def analyze_file(self, log_file):
        """Analisa arquivo de log completo"""
        print(f"[*] Analisando arquivo: {log_file}")
        total_alerts = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    alerts = self.analyze_log_line(line)
                    for alert in alerts:
                        self.save_alert(alert)
                        total_alerts.append(alert)
                        self.print_alert(alert)
            
            print(f"\n[+] Análise concluída: {len(total_alerts)} alertas gerados")
            self.generate_report()
            
        except FileNotFoundError:
            print(f"[!] Erro: Arquivo {log_file} não encontrado")
        except Exception as e:
            print(f"[!] Erro ao analisar arquivo: {e}")
    
    def print_alert(self, alert):
        """Exibe alerta formatado"""
        colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'LOW': '\033[92m'
        }
        reset = '\033[0m'
        
        color = colors.get(alert['severity'], '')
        print(f"\n{color}[ALERTA {alert['severity']}]{reset}")
        print(f"Regra: {alert['rule_name']}")
        print(f"IP Origem: {alert['source_ip']}")
        print(f"Descrição: {alert['description']}")
        print(f"Ocorrências: {alert['count']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Log: {alert['log_entry'][:100]}...")
    
    def generate_report(self):
        """Gera relatório de segurança"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        print("\n" + "="*60)
        print("RELATÓRIO DE SEGURANÇA")
        print("="*60)
        
        # Alertas por severidade
        cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
        print("\nAlertas por Severidade:")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]}")
        
        # Top IPs suspeitos
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM alerts 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        print("\nTop 5 IPs Suspeitos:")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]} alertas")
        
        # Ataques mais comuns
        cursor.execute('''
            SELECT rule_name, COUNT(*) as count 
            FROM alerts 
            GROUP BY rule_name 
            ORDER BY count DESC
        ''')
        print("\nTipos de Ataques Detectados:")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]} ocorrências")
        
        conn.close()


def create_sample_logs():
    """Cria logs de exemplo para demonstração"""
    sample_logs = """
2025-01-30 10:15:23 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
2025-01-30 10:15:24 sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
2025-01-30 10:15:25 sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2
2025-01-30 10:15:26 sshd[1237]: Failed password for user from 192.168.1.100 port 22 ssh2
2025-01-30 10:15:27 sshd[1238]: Failed password for admin from 192.168.1.100 port 22 ssh2
2025-01-30 10:15:28 sshd[1239]: Failed password for root from 192.168.1.100 port 22 ssh2
2025-01-30 10:20:15 apache[5678]: 192.168.1.200 - - "GET /admin' OR '1'='1 HTTP/1.1" 200 1234
2025-01-30 10:21:30 apache[5679]: 192.168.1.200 - - "GET /../../etc/passwd HTTP/1.1" 403 512
2025-01-30 10:22:45 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 80/tcp
2025-01-30 10:22:46 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 443/tcp
2025-01-30 10:22:47 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 22/tcp
2025-01-30 10:22:48 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 21/tcp
2025-01-30 10:22:49 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 3389/tcp
2025-01-30 10:22:50 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 8080/tcp
2025-01-30 10:22:51 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 3306/tcp
2025-01-30 10:22:52 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 5432/tcp
2025-01-30 10:22:53 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 1433/tcp
2025-01-30 10:22:54 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 27017/tcp
2025-01-30 10:22:55 kernel: SYN packet from 10.0.0.50 to 192.168.1.10 6379/tcp
2025-01-30 10:30:00 sudo: user1 : COMMAND=/bin/bash
2025-01-30 10:35:00 apache[6789]: 192.168.1.150 - - "GET /users UNION SELECT * FROM passwords-- HTTP/1.1" 500 256
"""
    
    with open('/home/claude/cybersecurity-projects/siem-detector/sample_logs.txt', 'w') as f:
        f.write(sample_logs)
    
    print("[+] Arquivo de logs de exemplo criado: sample_logs.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SIEM Detector - Sistema de Detecção de Intrusão')
    parser.add_argument('-f', '--file', help='Arquivo de log para analisar')
    parser.add_argument('-s', '--sample', action='store_true', help='Criar logs de exemplo')
    
    args = parser.parse_args()
    
    if args.sample:
        create_sample_logs()
        args.file = 'sample_logs.txt'
    
    if args.file:
        detector = SIEMDetector()
        detector.analyze_file(args.file)
    else:
        parser.print_help()
