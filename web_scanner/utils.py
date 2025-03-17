import re
import tkinter.messagebox as messagebox


# Adiciona o HTTPS ou HTTP no link caso o usuário esqueça
def adicionar_https(event, entry_widget):
    url = entry_widget.get()
    if not url.startswith("https://") and not url.startswith("http://"):
        entry_widget.insert(0, "https://")


# Limpa os resultados exibidos no widget de texto
def limpar_resultados(txt_widget):
    txt_widget.delete('1.0', 'end')


# Verifica se a URL é válida
def verificar_url_valida(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// ou https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domínio
        r'localhost|'  # local
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ipv4
        r'\[?[A-F0-9]*:[A-F0-9]*:[A-F0-9]*:[A-F0-9]*:[A-F0-9]*:[A-F0-9]*:[A-F0-9]*:[A-F0-9]*\]?)'  # ipv6
        r'(?::\d+)?'  # porta
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None


# Formata a URL para adicionar "https://" caso o usuário não tenha incluído
def formatar_url(url):
    if not url.startswith("https://") and not url.startswith("http://"):
        return "https://" + url
    return url


# Limpa o campo de entrada
def limpar_entrada(entry_widget):
    entry_widget.delete(0, 'end')


# Exibe uma mensagem de erro
def mostrar_erro(mensagem):
    messagebox.showerror("Erro", mensagem)


# Exibe uma mensagem de sucesso
def mostrar_sucesso(mensagem):
    messagebox.showinfo("Sucesso", mensagem)


# Adiciona texto colorido no widget de texto
def adicionar_texto_com_cor(txt_widget, texto, cor):
    txt_widget.insert('end', texto)
    txt_widget.tag_add(cor, '1.0', 'end')
    txt_widget.tag_config(cor, foreground=cor)


# Salva o conteúdo do widget de texto em um arquivo
def salvar_em_arquivo(txt_widget, nome_arquivo="resultado.txt"):
    try:
        with open(nome_arquivo, "w") as file:
            file.write(txt_widget.get('1.0', 'end'))
        mostrar_sucesso(f"Arquivo '{nome_arquivo}' salvo com sucesso!")
    except Exception as e:
        mostrar_erro(f"Erro ao salvar o arquivo: {str(e)}")


# Converte o texto para maiúsculas
def converter_para_maiusculas(entry_widget):
    texto = entry_widget.get()
    entry_widget.delete(0, 'end')
    entry_widget.insert(0, texto.upper())


# Converte o texto para minúsculas
def converter_para_minusculas(entry_widget):
    texto = entry_widget.get()
    entry_widget.delete(0, 'end')
    entry_widget.insert(0, texto.lower())


# Conta a quantidade de caracteres no texto do widget de entrada
def contar_caracteres(entry_widget):
    texto = entry_widget.get()
    return len(texto)
