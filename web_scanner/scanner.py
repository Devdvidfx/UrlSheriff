import logging
import socket
import threading
from tkinter import END, INSERT
from urllib.parse import urlparse, urljoin

import requests
import validators
from Wappalyzer import Wappalyzer, WebPage
from bs4 import BeautifulSoup

# Configuração do sistema de logs
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

API_VIRUSTOTAL = "SUA_CHAVE_API"


def validar_url(url):
    return validators.url(url)


def verificar_virustotal(url, txt_widget):
    """Consulta a URL no VirusTotal."""
    try:
        headers = {"x-apikey": API_VIRUSTOTAL}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
        if response.status_code == 200:
            txt_widget.insert(INSERT, "URL verificada no VirusTotal. Veja o relatório.")
        else:
            txt_widget.insert(INSERT, "Não foi possível verificar a URL no VirusTotal.\n")
    except Exception as e:
        txt_widget.insert(INSERT, f"Erro ao verificar VirusTotal: {e}\n")


def scan_subdominios(url, txt_widget):
    """Escaneia subdomínios comuns de um domínio."""
    subdominios_comuns = ["www", "blog", "mail", "admin", "dev", "test"]
    dominio_base = url.replace("https://", "").replace("http://", "").split('/')[0]
    txt_widget.insert(INSERT, "\n🔍 Escaneando subdomínios...\n")

    for sub in subdominios_comuns:
        subdominio = f"https://{sub}.{dominio_base}"
        try:
            resposta = requests.get(subdominio, timeout=3)
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"✅ Subdomínio encontrado: {subdominio}\n")
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
            resposta = requests.get(url_teste, timeout=3)
            if resposta.status_code == 200:
                txt_widget.insert(INSERT, f"🚨 Diretório encontrado: {url_teste}\n")
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
        resposta_http = requests.get(url)
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
    portas_alvo = [80, 443, 8080]
    for porta in portas_alvo:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            resultado = s.connect_ex((host, porta))
            if resultado == 0:
                txt_widget.insert(INSERT, f'A porta {porta} está aberta\n')
            else:
                txt_widget.insert(INSERT, f'A porta {porta} está fechada\n')
            s.close()
        except Exception as ex:
            txt_widget.insert(INSERT, f'Erro ao verificar a porta {porta}: {ex}\n')


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
