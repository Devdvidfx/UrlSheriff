import os
from tkinter import Tk, Label, Entry, Button, scrolledtext, PhotoImage, WORD
from tkinter.filedialog import asksaveasfilename
from .utils import adicionar_https, limpar_resultados
from .scanner import executar_varredura, verificar_portas_abertas, verificar_links_externos


def start_interface():
    # Cria a janela principal
    janela = Tk()
    janela.title('Ferramenta de Varredura de Sites')
    janela.geometry('800x600')

    # Caminho para os ícones
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'resources', 'icons')

    # Cria um rótulo para a entrada da URL
    lbl1 = Label(janela, text='Insira a URL do site a ser verificado:')
    lbl1.grid(row=0, column=0, padx=10, pady=10)

    # Cria uma entrada para a URL do site
    entry = Entry(janela, width=40)
    entry.grid(row=0, column=1, padx=10, pady=10)

    # Adiciona evento para adicionar "https://" automaticamente
    entry.bind("<Return>", lambda event: adicionar_https(event, entry))

    # Cria um botão para iniciar a varredura
    btn_executar = Button(janela, text='Executar', command=lambda: executar_varredura(entry.get(), txt))
    btn_executar.grid(row=0, column=2, padx=10, pady=10)

    # Cria um botão para limpar os resultados
    btn_limpar = Button(janela, text='Limpar Resultados', command=lambda: limpar_resultados(txt))
    btn_limpar.grid(row=0, column=4, padx=10, pady=10)

    # Cria um botão para verificar links externos
    btn_links_externos = Button(janela, text='Verificar Links Externos',
                                command=lambda: verificar_links_externos(entry.get(), txt))
    btn_links_externos.grid(row=0, column=5, padx=10, pady=10)

    # Cria um botão para salvar os resultados
    btn_salvar = Button(janela, text='Salvar Arquivo', command=lambda: salvar_resultados(txt))
    btn_salvar.grid(row=0, column=3, padx=10, pady=10)

    # Cria uma área de texto para exibir os resultados
    txt = scrolledtext.ScrolledText(janela, wrap=WORD)
    txt.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

    # Loop principal da janela
    janela.mainloop()


def salvar_resultados(txt_widget):
    conteudo = txt_widget.get("1.0", "end-1c")
    filename = asksaveasfilename(defaultextension=".txt")
    if filename:
        with open(filename, 'w') as f:
            f.write(conteudo)
