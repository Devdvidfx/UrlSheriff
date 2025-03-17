import logging
import os
import socket
import ssl
import threading
from tkinter import END, INSERT
from urllib.parse import urlparse, urljoin

import dns.resolver
import requests
import validators
import whois
from Wappalyzer import Wappalyzer, WebPage
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Configuração do sistema de logs
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

load_dotenv(".env")

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if API_KEY is None:
    raise ValueError("⚠️ A chave da API do VirusTotal não foi encontrada! Verifique o arquivo .env.")

headers = {
    "x-apikey": API_KEY
}

def validar_url(url):
    return validators.url(url)


def verificar_virustotal(url, txt_widget):
    """Consulta a URL no VirusTotal."""
    try:
        logging.info(f"Consultando VirusTotal para a URL: {url}")
        headers = {"x-apikey": API_KEY}
        data = {"url": url}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=10
        )
        response.raise_for_status()

        if response.status_code == 200:
            json_resp = response.json()
            if "data" in json_resp and "id" in json_resp["data"]:
                analysis_id = json_resp["data"]["id"]
                report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                               headers=headers)

                if report_response.status_code == 200:
                    resultado = report_response.json()
                    txt_widget.insert("end",
                                      f"URL analisada no VirusTotal! Status: {resultado['data']['attributes']['status']}\n")
                    logging.info(f"Análise concluída com status {resultado['data']['attributes']['status']}")
                else:
                    raise ValueError("Erro ao obter relatório do VirusTotal.")
            else:
                raise ValueError("Erro ao processar resposta do VirusTotal.")
        else:
            raise ValueError("Erro ao enviar URL para análise no VirusTotal.")
    except Exception as e:
        logging.error(f"Erro ao verificar VirusTotal para a URL {url}: {e}")
        txt_widget.insert("end", f"Erro ao verificar VirusTotal: {e}\n")

def scan_subdominios(url, txt_widget):
    """Escaneia subdomínios comuns de um domínio."""
    subdominios_comuns = ["www", "blog", "mail", "admin", "dev", "test"]
    dominio_base = url.replace("https://", "").replace("http://", "").split('/')[0]
    txt_widget.insert(INSERT, "\n🔍 Escaneando subdomínios...\n")

    for sub in subdominios_comuns:
        subdominio = f"https://{sub}.{dominio_base}"
        try:
            resposta = requests.get(subdominio, timeout=5)  # Aumentado timeout para evitar falsos negativos
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"✅ Subdomínio encontrado: {subdominio}\n")
        except requests.exceptions.Timeout:
            txt_widget.insert(INSERT, f"⏳ Timeout ao acessar {subdominio}. O site pode estar lento ou indisponível.\n")
        except requests.exceptions.RequestException:
            pass


def verificar_headers(url, txt_widget):
    """Verifica os cabeçalhos HTTP de uma URL."""
    try:
        resposta = requests.head(url, timeout=5)
        txt_widget.insert(INSERT, "\n📌 Analisando headers HTTP...\n")
        for chave, valor in resposta.headers.items():
            txt_widget.insert(INSERT, f"{chave}: {valor}\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar headers: {e}\n")


def verificar_tecnologias(url, txt_widget):
    """Detecta tecnologias usadas em um site."""
    try:
        wappalyzer = Wappalyzer.latest()
        pagina = WebPage.new_from_url(url)
        tecnologias = wappalyzer.analyze(pagina)
        txt_widget.insert(INSERT, "\n🛠️ Detectando tecnologias...\n")
        for tecnologia in tecnologias:
            txt_widget.insert(INSERT, f"✅ Tecnologia detectada: {tecnologia}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"❌ Erro ao detectar tecnologias: {e}\n")


def forca_bruta_diretorios(url, txt_widget):
    """Testa diretórios comuns no site."""
    diretorios_comuns = ["admin", "backup", "config", "database", "uploads"]
    txt_widget.insert(INSERT, "\n🔎 Testando diretórios sensíveis...\n")

    for diretorio in diretorios_comuns:
        url_teste = f"{url}/{diretorio}/"
        try:
            resposta = requests.get(url_teste, timeout=5)  # Aumentado timeout
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"🚨 Diretório encontrado: {url_teste}\n")
        except requests.exceptions.Timeout:
            txt_widget.insert(INSERT, f"⏳ Timeout ao testar {url_teste}. O servidor não respondeu a tempo.\n")
        except requests.exceptions.RequestException:
            pass


def verificar_seguranca(url, txt_widget):
    """Verifica se o site usa HTTPS e se os cookies são seguros."""
    try:
        resposta = requests.get(url, timeout=5)

        if resposta.url.startswith("https://"):
            txt_widget.insert(INSERT, "✅ O site usa HTTPS.\n")
        else:
            txt_widget.insert(INSERT, "⚠️ O site não usa HTTPS.\n")

        headers = resposta.headers
        if "Strict-Transport-Security" in headers:
            txt_widget.insert(INSERT, "✅ HSTS está habilitado.\n")
        else:
            txt_widget.insert(INSERT, "⚠️ HSTS não está habilitado.\n")

        if "Set-Cookie" in headers:
            cookies = headers["Set-Cookie"]
            if "Secure" in cookies:
                txt_widget.insert(INSERT, "✅ Cookies marcados como Secure.\n")
            else:
                txt_widget.insert(INSERT, "⚠️ Cookies sem flag Secure.\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar segurança: {e}\n")


def executar_varredura(url, txt_widget):
    if not validar_url(url):
        txt_widget.insert(INSERT, "URL inválida.\n")
        return

    threading.Thread(target=executar_varredura_thread, args=(url, txt_widget)).start()


def executar_varredura_thread(url, txt_widget):
    txt_widget.delete('1.0', END)

    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resposta_http = requests.get(url, headers=headers)
        resposta_http.raise_for_status()
        texto_html = resposta_http.text
        soup = BeautifulSoup(texto_html, 'html.parser')

        for link in soup.find_all('a'):
            if 'admin' in link.get('href', ''):
                txt_widget.insert(INSERT, f'Potencial área administrativa encontrada: {link.get("href")}\n')

        formulario = soup.find('form')
        if formulario:
            txt_widget.insert(INSERT, 'Formulário de login encontrado.\n')

        imagens = soup.find_all('img')
        txt_widget.insert(INSERT, f'\nTotal de imagens encontradas: {len(imagens)}\n')
        for img in imagens:
            txt_widget.insert(INSERT, f'URL da imagem: {urljoin(url, img["src"])}\n')

        verificar_links_externos(soup, url, txt_widget)
        verificar_portas_abertas(url, txt_widget)
        verificar_virustotal(url, txt_widget)
        scan_subdominios(url, txt_widget)
        verificar_headers(url, txt_widget)
        verificar_tecnologias(url, txt_widget)
        forca_bruta_diretorios(url, txt_widget)
        verificar_seguranca(url, txt_widget)

        logging.info(f"Varredura concluída para {url}")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f'Erro ao acessar a URL: {e}\n')
        logging.error(f"Erro ao acessar {url}: {e}")


def verificar_portas_abertas(url, txt_widget):
    host = urlparse(url).hostname
    if not host:
        txt_widget.insert(INSERT, "⚠️ Não foi possível determinar o host.\n")
        return

    portas_alvo = [80, 443, 8080, 21, 22, 3306, 5432]
    for porta in portas_alvo:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((host, porta)) == 0:
                    txt_widget.insert(INSERT, f'✅ Porta {porta} aberta em {host}\n')
                else:
                    txt_widget.insert(INSERT, f'❌ Porta {porta} fechada em {host}\n')
        except Exception as ex:
            txt_widget.insert(INSERT, f'⚠️ Erro ao verificar a porta {porta}: {ex}\n')


def verificar_links_externos(soup, url, txt_widget):
    links_externos = set()
    for link in soup.find_all('a', href=True):
        link_absoluto = urljoin(url, link['href'])
        if urlparse(link_absoluto).netloc != urlparse(url).netloc:
            links_externos.add(link_absoluto)
    if links_externos:
        txt_widget.insert(INSERT, '\nLinks externos encontrados:\n')
        for link in links_externos:
            txt_widget.insert(INSERT, f'{link}\n')
    else:
        txt_widget.insert(INSERT, 'Nenhum link externo encontrado.\n')


def verificar_vulnerabilidades(tecnologia, txt_widget):
    """Verifica vulnerabilidades conhecidas de uma tecnologia específica."""
    try:
        cve_url = f"https://cve.circl.lu/api/cvefor/{tecnologia}/"
        resposta = requests.get(cve_url)
        if resposta.status_code == 200:
            cve_data = resposta.json()
            if cve_data:
                txt_widget.insert(INSERT, f"Vulnerabilidades encontradas para {tecnologia}:\n")
                for cve in cve_data:
                    txt_widget.insert(INSERT, f"CVE-{cve['id']}: {cve['summary']}\n")
            else:
                txt_widget.insert(INSERT, f"Nenhuma vulnerabilidade conhecida para {tecnologia}.\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar vulnerabilidades: {e}\n")


def testar_sql_injection(url, txt_widget):
    """Testa vulnerabilidade a SQL Injection em formulários."""
    payloads = ["' OR 1=1 --", '" OR 1=1 --', "' OR 'a'='a"]
    try:
        resposta = requests.get(url)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        form = soup.find('form')
        if form:
            for payload in payloads:
                data = {input_tag['name']: payload for input_tag in form.find_all('input')}
                resposta_sql = requests.post(url, data=data)
                if "error" in resposta_sql.text or "syntax" in resposta_sql.text:
                    txt_widget.insert(INSERT, f"⚠️ Potencial SQL Injection encontrado em {url}\n")
                    return
    except Exception as e:
        txt_widget.insert(INSERT, f"❌ Erro ao testar SQL Injection: {e}\n")


def testar_xss(url, txt_widget):
    """Testa vulnerabilidade a XSS em formulários."""
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
    try:
        resposta = requests.get(url)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        form = soup.find('form')
        if form:
            for payload in payloads:
                data = {input_tag['name']: payload for input_tag in form.find_all('input')}
                resposta_xss = requests.post(url, data=data)
                if payload in resposta_xss.text:
                    txt_widget.insert(INSERT, f"⚠️ Potencial XSS encontrado em {url}\n")
                    return
    except Exception as e:
        txt_widget.insert(INSERT, f"❌ Erro ao testar XSS: {e}\n")


def verificar_links_quebrados(url, txt_widget):
    """Verifica links internos quebrados no site."""
    try:
        resposta = requests.get(url)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            link_url = urljoin(url, link['href'])
            if urlparse(link_url).netloc == urlparse(url).netloc:
                resposta_link = requests.head(link_url, timeout=5)
                if resposta_link.status_code == 404:
                    txt_widget.insert(INSERT, f"❌ Link quebrado encontrado: {link_url}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar links quebrados: {e}\n")


def verificar_arquivos_sensiveis(url, txt_widget):
    """Verifica arquivos sensíveis no site."""
    arquivos_sensiveis = ["config.php", "wp-config.php", "backup.sql", "database.backup"]
    for arquivo in arquivos_sensiveis:
        url_teste = f"{url}/{arquivo}"
        try:
            resposta = requests.get(url_teste, timeout=5)
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"🚨 Arquivo sensível encontrado: {url_teste}\n")
        except requests.exceptions.Timeout:
            txt_widget.insert(INSERT, f"⏳ Timeout ao testar {url_teste}. O servidor não respondeu a tempo.\n")
        except requests.exceptions.RequestException:
            pass


def verificar_cookies(url, txt_widget):
    """Verifica cookies com flag HttpOnly e SameSite."""
    try:
        resposta = requests.get(url, timeout=5)
        headers = resposta.headers
        if "Set-Cookie" in headers:
            cookies = headers["Set-Cookie"]
            if "HttpOnly" in cookies:
                txt_widget.insert(INSERT, "✅ Cookie com flag HttpOnly.\n")
            else:
                txt_widget.insert(INSERT, "⚠️ Cookie sem flag HttpOnly.\n")

            if "SameSite" in cookies:
                txt_widget.insert(INSERT, "✅ Cookie com flag SameSite.\n")
            else:
                txt_widget.insert(INSERT, "⚠️ Cookie sem flag SameSite.\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar cookies: {e}\n")


def verificar_redirecionamentos(url, txt_widget):
    """Verifica redirecionamentos maliciosos no site."""
    try:
        resposta = requests.get(url, allow_redirects=True)
        for redirecionamento in resposta.history:
            if "suspicious" in redirecionamento.url:
                txt_widget.insert(INSERT, f"⚠️ Redirecionamento suspeito detectado: {redirecionamento.url}\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"❌ Erro ao verificar redirecionamentos: {e}\n")


def verificar_dns(url, txt_widget):
    try:
        dominio = urlparse(url).hostname
        respostas = dns.resolver.resolve(dominio, 'A')
        txt_widget.insert(INSERT, f"Registros DNS encontrados para {dominio}:\n")
        for resposta in respostas:
            txt_widget.insert(INSERT, f"IP: {resposta.to_text()}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar DNS: {e}\n")


def verificar_codigo_http(url, txt_widget):
    try:
        resposta = requests.get(url)
        txt_widget.insert(INSERT, f"Código HTTP: {resposta.status_code}\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"Erro ao verificar código HTTP: {e}\n")


def verificar_ssl(url, txt_widget):
    hostname = urlparse(url).hostname
    port = 443
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as s:
            s.connect((hostname, port))
            cert = s.getpeercert()
            txt_widget.insert(INSERT, f"Certificado SSL encontrado: {cert}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar SSL: {e}\n")


def verificar_robots_txt(url, txt_widget):
    robots_url = urljoin(url, "/robots.txt")
    try:
        resposta = requests.get(robots_url)
        if resposta.status_code == 200:
            txt_widget.insert(INSERT, f"Arquivo robots.txt encontrado:\n{resposta.text}\n")
        else:
            txt_widget.insert(INSERT, "Arquivo robots.txt não encontrado.\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar robots.txt: {e}\n")


def verificar_cabecalhos_seguranca(url, txt_widget):
    try:
        resposta = requests.head(url, timeout=5)
        txt_widget.insert(INSERT, "\n🔒 Verificando cabeçalhos de segurança...\n")
        cabecalhos_seguranca = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
        for cabecalho in cabecalhos_seguranca:
            if cabecalho in resposta.headers:
                txt_widget.insert(INSERT, f"{cabecalho}: {resposta.headers[cabecalho]}\n")
            else:
                txt_widget.insert(INSERT, f"⚠️ {cabecalho} não encontrado.\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"Erro ao verificar cabeçalhos de segurança: {e}\n")


def verificar_robots_txt(url, txt_widget):
    robots_url = urljoin(url, "/robots.txt")
    try:
        resposta = requests.get(robots_url)
        if resposta.status_code == 200:
            txt_widget.insert(INSERT, f"Arquivo robots.txt encontrado:\n{resposta.text}\n")
        else:
            txt_widget.insert(INSERT, "Arquivo robots.txt não encontrado.\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar robots.txt: {e}\n")


def verificar_cabecalhos_seguranca(url, txt_widget):
    try:
        resposta = requests.head(url, timeout=5)
        txt_widget.insert(INSERT, "\n🔒 Verificando cabeçalhos de segurança...\n")
        cabecalhos_seguranca = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
        for cabecalho in cabecalhos_seguranca:
            if cabecalho in resposta.headers:
                txt_widget.insert(INSERT, f"{cabecalho}: {resposta.headers[cabecalho]}\n")
            else:
                txt_widget.insert(INSERT, f"⚠️ {cabecalho} não encontrado.\n")
    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f"Erro ao verificar cabeçalhos de segurança: {e}\n")


def verificar_email_autenticacao(dominio, txt_widget):
    try:
        # Verificando registros SPF, DKIM e DMARC
        txt_widget.insert(INSERT, f"Verificando registros de autenticação de e-mail para {dominio}...\n")
        spf = dns.resolver.resolve(dominio, 'TXT')
        for record in spf:
            if 'v=spf1' in record.to_text():
                txt_widget.insert(INSERT, f"SPF: {record.to_text()}\n")

        dkim = dns.resolver.resolve(f'_domainkey.{dominio}', 'TXT')
        for record in dkim:
            txt_widget.insert(INSERT, f"DKIM: {record.to_text()}\n")

        dmarc = dns.resolver.resolve(f'_dmarc.{dominio}', 'TXT')
        for record in dmarc:
            txt_widget.insert(INSERT, f"DMARC: {record.to_text()}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar autenticação de e-mail: {e}\n")


def verificar_vazamento_dados(url, txt_widget):
    vazamentos = ["config", "admin", "db", "backup", "upload", "test"]
    for vazamento in vazamentos:
        url_teste = f"{url}/{vazamento}"
        try:
            resposta = requests.get(url_teste, timeout=5)
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"⚠️ Potencial vazamento de dados encontrado: {url_teste}\n")
        except requests.exceptions.RequestException:
            pass


def verificar_whois(url, txt_widget):
    try:
        dominio = urlparse(url).hostname
        resultado_whois = whois.whois(dominio)
        txt_widget.insert(INSERT, f"\nInformações WHOIS para {dominio}:\n")
        for chave, valor in resultado_whois.items():
            txt_widget.insert(INSERT, f"{chave}: {valor}\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar WHOIS: {e}\n")
