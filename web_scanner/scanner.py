import socket
import requests
from bs4 import BeautifulSoup
from tkinter import END, INSERT
from urllib.parse import urlparse, urljoin


def executar_varredura(url, txt_widget):
    # Limpa a área de resultados
    txt_widget.delete('1.0', END)

    # Adiciona o prefixo "https://" se não estiver presente
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    try:
        # Faz uma requisição GET para a URL
        resposta_http = requests.get(url)
        resposta_http.raise_for_status()  # Lança uma exceção para erros HTTP
        texto_html = resposta_http.text

        # Parceia o HTML da página usando o BeautifulSoup
        soup = BeautifulSoup(texto_html, 'html.parser')

        # Procura por links que poderiam ser vulneráveis a ataques de força bruta
        for link in soup.find_all('a'):
            # Verifica se o link parece ser uma área restrita
            if 'admin' in link.get('href'):
                txt_widget.insert(INSERT, f'Potencial área administrativa encontrada: {link.get("href")}\n')

        # Verifica se a página possui um formulário de login
        formulario = soup.find('form')
        if formulario:
            txt_widget.insert(INSERT, 'Formulário de login encontrado.\n')

        # Exibe a quantidade total de imagens e os URLs das imagens
        imagens = soup.find_all('img')
        txt_widget.insert(INSERT, f'\nTotal de imagens encontradas: {len(imagens)}\n')
        for img in imagens:
            txt_widget.insert(INSERT, f'URL da imagem: {urljoin(url, img["src"])}\n')

        # Exibe links externos
        links_externos = set()
        for link in soup.find_all('a', href=True):
            link_absoluto = urljoin(url, link['href'])
            if urlparse(link_absoluto).netloc != urlparse(url).netloc:
                links_externos.add(link_absoluto)
        if links_externos:
            txt_widget.insert(INSERT, '\nLinks externos encontrados:\n')
            for link in links_externos:
                txt_widget.insert(INSERT, f'{link}\n')

        verificar_portas_abertas(url, txt_widget)

    except requests.exceptions.RequestException as e:
        txt_widget.insert(INSERT, f'Erro ao acessar a URL: {e}\n')


def verificar_portas_abertas(url, txt_widget):
    # Obtem o nome do host a partir da URL
    host = urlparse(url).hostname

    # Lista de portas para verificar
    portas_alvo = [80, 443, 8080]

    # Tenta se conectar a cada porta
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


# aqui foi adionada uma nova funcionalidade.

def verificar_links_externos(soup, url, txt_widget):
    # Limpa a área de resultados
    txt_widget.delete('1.0', END)

    # Conjunto para armazenar os links externos encontrados
    links_externos = set()

    # Verifica todos os links na página
    for link in soup.find_all('a', href=True):
        link_absoluto = urljoin(url, link['href'])

        # Verifica se o link absoluto não pertence ao mesmo domínio da URL fornecida
        if urlparse(link_absoluto).netloc != urlparse(url).netloc:
            links_externos.add(link_absoluto)

    # Se links externos foram encontrados, exibe-os na área de resultados
    if links_externos:
        txt_widget.insert(INSERT, '\nLinks externos encontrados:\n')
        for link in links_externos:
            txt_widget.insert(INSERT, f'{link}\n')
    else:
        txt_widget.insert(INSERT, 'Nenhum link externo encontrado.\n')
