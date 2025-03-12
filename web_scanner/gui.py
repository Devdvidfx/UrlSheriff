import os
from tkinter import Tk, Label, Entry, Button, scrolledtext, WORD, Frame, Menu
from tkinter.filedialog import asksaveasfilename

from .scanner import executar_varredura, verificar_links_externos
from .utils import adicionar_https, \
    limpar_resultados  # Assegure-se que essas funções estão implementadas no arquivo 'utils.py'


def start_interface():
    # Cria a janela principal
    janela = Tk()
    janela.title('Ferramenta de Varredura de Sites - '
                 'Dev: Davi Felipe')
    janela.geometry('800x600')

    # Caminho para os ícones (ajuste conforme necessário)
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'resources', 'icons')

    # Cria um frame principal para organizar a interface
    frame_principal = Frame(janela)
    frame_principal.pack(fill="both", expand=True, padx=10, pady=10)

    # Cria um frame para a entrada de URL e os botões principais
    frame_input = Frame(frame_principal)
    frame_input.pack(fill="x", pady=10)

    # Cria um rótulo para a entrada da URL
    lbl1 = Label(frame_input, text='Insira a URL do site a ser verificado:')
    lbl1.pack(side="left", padx=10)

    # Cria uma entrada para a URL do site
    entry = Entry(frame_input, width=40, font=("Arial", 12))
    entry.pack(side="left", padx=10)

    # Adiciona evento para adicionar "https://" automaticamente
    entry.bind("<Return>", lambda event: adicionar_https(event, entry))

    # Função para iniciar a varredura
    def start_scan():
        executar_varredura(entry.get(), txt)
        btn_executar.config(state="disabled")  # Desativa o botão de executar após começar a varredura
        btn_parar.config(state="normal")  # Ativa o botão de parar varredura

    # Função para parar a varredura
    def stop_scan():
        # Aqui você pode adicionar a lógica para interromper a varredura, por exemplo, se tiver uma thread rodando
        btn_executar.config(state="normal")  # Habilita o botão de executar
        btn_parar.config(state="disabled")  # Desativa o botão de parar

    # Cria o botão para iniciar a varredura
    btn_executar = Button(frame_input, text='Executar Varredura', command=start_scan, bg="#4CAF50", fg="white",
                          font=("Arial", 8), relief="raised", bd=3)
    btn_executar.pack(side="left", padx=5, pady=5)

    # Cria o botão para parar a varredura
    btn_parar = Button(frame_input, text='Parar Varredura', command=stop_scan, bg="#f44336", fg="white",
                       font=("Arial", 8), relief="raised", bd=3, state="disabled")
    btn_parar.pack(side="left", padx=5, pady=5)

    # Cria um frame para os resultados da varredura
    frame_resultados = Frame(frame_principal)
    frame_resultados.pack(fill="both", expand=True)

    # Cria uma área de texto para exibir os resultados
    txt = scrolledtext.ScrolledText(frame_resultados, wrap=WORD, font=("Arial", 12))
    txt.pack(fill="both", expand=True, padx=10, pady=10)

    # Funções para o menu de opções
    def limpar():
        limpar_resultados(txt)

    def verificar_links():
        verificar_links_externos(entry.get(), txt)

    def salvar():
        conteudo = txt.get("1.0", "end-1c")
        filename = asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write(conteudo)

    # Cria o menu de opções no canto superior direito
    menu_bar = Menu(janela)
    janela.config(menu=menu_bar)

    # Adiciona as opções ao menu
    menu_opcoes = Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Opções", menu=menu_opcoes)
    menu_opcoes.add_command(label="Limpar Resultados", command=limpar)
    menu_opcoes.add_command(label="Verificar Links Externos", command=verificar_links)
    menu_opcoes.add_command(label="Salvar Arquivo", command=salvar)

    # Loop principal da janela
    janela.mainloop()

def salvar_resultados(txt_widget):
    conteudo = txt_widget.get("1.0", "end-1c")
    filename = asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if filename:
        with open(filename, 'w') as f:
            f.write(conteudo)
