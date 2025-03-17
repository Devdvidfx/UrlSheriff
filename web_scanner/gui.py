import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='Wappalyzer')
import webbrowser
import time
from tkinter import Tk, ttk, Label, Entry, Button, scrolledtext, WORD, Frame, Menu, filedialog, Toplevel
from tkinter.filedialog import asksaveasfilename

from .scanner import *
from .utils import *


def criar_botao_limpar(txt_widget):
    return Button(janela, text="Limpar", command=lambda: limpar_resultados(txt_widget))

def start_interface():
    # Cria a janela principal
    janela = Tk()
    janela.title('Ferramenta de Varredura de Sites - Dev: Davi Felipe')
    janela.geometry('800x600')

    # Cria um frame principal para organizar a interface
    frame_principal = Frame(janela)
    frame_principal.pack(fill="both", expand=True, padx=10, pady=10)

    # Frame para a entrada da URL e botões principais
    frame_input = Frame(frame_principal)
    frame_input.pack(fill="x", pady=10, expand=True)

    # Rótulo e campo de entrada para a URL
    lbl1 = Label(frame_input, text='Insira a URL do site')
    lbl1.pack(side="left", padx=10)

    entry = Entry(frame_input, width=40, font=("Arial", 12))
    entry.pack(side="left", padx=10)

    entry.bind("<Return>", lambda event: adicionar_https(event, entry))

    # Barra de progresso
    progress = ttk.Progressbar(frame_principal, orient="horizontal", length=300, mode="determinate")
    progress.pack(pady=10)

    # Função para iniciar a varredura
    def start_scan():
        btn_executar.config(state="disabled")
        btn_parar.config(state="normal")
        progress.config(value=0, maximum=100)  # Resetando a barra
        for i in range(100):  # Simula o progresso
            progress.config(value=i)
            janela.update_idletasks()  # Atualiza a interface
            # Simulação de trabalho (substitua isso pelo código real de varredura)
            time.sleep(0.1)
        executar_varredura(entry.get(), txt)

    # Função para parar a varredura
    def stop_scan():
        btn_executar.config(state="normal")
        btn_parar.config(state="disabled")

    icon_path = os.path.join(os.path.dirname(__file__), 'resources', 'icons')

    # Botão "Iniciar" com cor personalizada
    btn_executar = Button(frame_input, text="Iniciar", command=start_scan, relief="raised", bd=3, width=10, height=2,
                          fg="white", bg="green")
    btn_executar.pack(side="left", padx=5, pady=5)

    # Botão "Parar" com cor personalizada
    btn_parar = Button(frame_input, text="Parar", command=stop_scan, relief="raised", bd=3, width=10, height=2,
                       fg="white", bg="red", state="disabled")
    btn_parar.pack(side="left", padx=5, pady=5)

    # Cria um frame para os resultados da varredura
    frame_resultados = Frame(frame_principal)
    frame_resultados.pack(fill="both", expand=True, pady=10)

    # Cria uma área de texto para exibir os resultados
    txt = scrolledtext.ScrolledText(frame_resultados, wrap=WORD, font=("Arial", 12))
    txt.pack(fill="both", expand=True, padx=10, pady=10)

    """Funções do menu"""

    def limpar():
        limpar_resultados(txt)

    def verificar_links(txt_widget=None):
        verificar_links_externos(entry.get(), txt_widget)

    def salvar():
        salvar_resultados(txt)

    """Opção Arquivo"""

    def abrir_arquivo():
        try:
            filename = filedialog.askopenfilename(defaultextension=".txt",
                                                  filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if filename:
                with open(filename, 'r') as file:
                    conteudo = file.read()
                    txt.delete(1.0, "end")  # Limpa o conteúdo atual
                    txt.insert("1.0", conteudo)  # Insere o conteúdo do arquivo na área de texto
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir o arquivo: {str(e)}")

    """Opção Compartilhar"""

    def compartilhar():
        conteudo = txt.get("1.0", "end-1c")  # Obtém o conteúdo da área de texto
        if conteudo:
            messagebox.showinfo("Compartilhar", "Conteúdo compartilhado com sucesso!")
        else:
            messagebox.showwarning("Aviso", "Não há conteúdo para compartilhar.")

    """Sobre"""

    # Função para exibir o "Sobre"
    def mostrar_sobre():
        messagebox.showinfo("Sobre",
                            "Ferramenta de Varredura de Sites"
                            "\nDesenvolvido por Davi Felipe"
                            "\nEste é um software para realizar Varreduras em sites e "
                            "Verificar links externos.")

    # Função para exibir a ajuda
    def mostrar_ajuda():
        texto_ajuda = (
            "Precisa de ajuda ou tem alguma dúvida sobre o funcionamento da ferramenta?\n\n"
            "Entre em contato para suporte através do e-mail: davifelipedev@gmail.com.\n\n"
            "Fique à vontade para me enviar suas perguntas, dúvidas ou feedbacks. Estarei sempre disponível para ajudar!\n\n"
            "Além disso, você pode explorar mais recursos, tutoriais e atualizações em meu GitHub:\n"
            "github.com/Devdvidfx\n\n"
            "Lá, você encontrará o código-fonte do projeto, exemplos e outras informações úteis para aprimorar seu uso da ferramenta."
        )

        messagebox.showinfo("Ajuda", texto_ajuda)

    def mostrar_versao():
        texto_versao = (
            "Versão 1.0.1\n\n"
            "Lançada em 2024.\n\n"
            "Esta versão inclui melhorias importantes na interface e na funcionalidade de varredura de sites.\n"
            "Ela corrige bugs menores e melhora a experiência geral do usuário. Novas funcionalidades, como a verificação de links externos e "
            "a adição de recursos no menu, foram introduzidas para otimizar o processo de análise de sites e facilitar o uso da ferramenta."
        )

        messagebox.showinfo("Versão", texto_versao)

    def mostrar_licenca():
        texto_licenca = (
            "Este software é licenciado sob a MIT License.\n\n"
            "A MIT License é uma licença permissiva, o que significa que você pode:\n"
            "- Usar, copiar, modificar, mesclar, publicar, distribuir, sublicenciar e/ou vender cópias do software;\n"
            "- Modificar o software para seus próprios fins;\n"
            "- Distribuir o software como parte de projetos comerciais ou não comerciais.\n\n"
            "A única condição é que você deve incluir o aviso de copyright e a licença em todas as cópias ou partes substanciais do software.\n\n"
            "Este software é fornecido 'no estado em que se encontra', sem qualquer garantia expressa ou implícita, incluindo, mas não se limitando a, garantias de "
            "comercialização, adequação a um fim específico e não violação. Em nenhum caso os autores ou detentores dos direitos autorais serão responsáveis por "
            "qualquer reclamação, dano ou outra responsabilidade, seja em uma ação de contrato, delito ou outro, decorrente de ou em conexão com o software ou o uso "
            "ou outros negócios no software."
        )

        messagebox.showinfo("Licença", texto_licenca)

    # Função para abrir o link da documentação no GitHub
    def abrir_documentacao():
        url = "https://github.com/Devdvidfx/UrlSheriff/blob/master/README.md"  # Substitua pelo link real do seu repositório
        webbrowser.open(url)

    "Funções para as Prefências"

    # Funções para Preferências
    def alterar_diretorio_salvamento(diretoriorio=None):
        # Lógica para o usuário selecionar o diretório onde os arquivos serão salvos
        diretorio = asksaveasfilename(title="Escolha o diretório de salvamento")
        if diretorio:
            print(f"Novo diretório selecionado: {diretoriorio}")
            # Você pode armazenar essa informação em um arquivo de configuração ou variável
            # para uso futuro em seu programa

    def configurar_notificacoes():
        # Exemplo de lógica para configurar notificações
        print("Configurações de notificações. Você pode ativar ou desativar notificações.")
        # Aqui você pode mostrar uma janela para o usuário selecionar se quer ou não receber notificações

    # Função para alterar o tema da interface (escuro/claro)
    def alternar_tema():
        if janela.option_get('theme', 'light') == 'light':
            janela.tk_setPalette(background='#2e2e2e', foreground='#ffffff')
            janela.option_add('*TButton*highlightBackground', '#555555')
            janela.option_add('*TButton*highlightColor', '#555555')
            janela.option_add('*TButton*highlightThickness', 3)
            janela.option_add('*font', ('Arial', 12))
            janela.option_add('theme', 'dark')
            # Alterar fundo e cor do botão
            for widget in frame_principal.winfo_children():
                if isinstance(widget, Button):
                    widget.config(bg="darkred", fg="white")
            print("Tema alternado para escuro.")
        else:
            janela.tk_setPalette(background='#ffffff', foreground='#000000')
            janela.option_add('*TButton*highlightBackground', '#DDDDDD')
            janela.option_add('*TButton*highlightColor', '#DDDDDD')
            janela.option_add('*TButton*highlightThickness', 3)
            janela.option_add('*font', ('Arial', 12))
            janela.option_add('theme', 'light')
            # Alterar fundo e cor do botão
            for widget in frame_principal.winfo_children():
                if isinstance(widget, Button):
                    widget.config(bg="green", fg="white")
            print("Tema alternado para claro.")

    def alterar_cor_fundo():
        def aplicar_cor(cor):
            janela.configure(bg=cor)
            print(f"Cor de fundo alterada para {cor}.")
            top.destroy()

        top = Toplevel(janela)
        top.title("Escolher Cor de Fundo")

        label = Label(top, text="Escolha a cor de fundo:")
        label.pack(pady=10)

        cores = ['#ffffff', '#f0f0f0', '#000000', '#2e2e2e', '#add8e6', '#ff6347', '#90ee90']

        for cor in cores:
            button = Button(top, text=cor, command=lambda cor=cor: aplicar_cor(cor))
            button.pack(pady=5)

    # Função única para alterar o tamanho da fonte
    def alterar_tamanho_fonte():
        def aplicar_tamanho(tamanho):
            janela.option_add("*font", ("Arial", tamanho))  # Usando a janela principal
            print(f"Tamanho da fonte alterado para {tamanho}.")
            top.destroy()

        top = Toplevel(janela)  # Use a janela principal como parent
        top.title("Escolher Tamanho da Fonte")
        top.geometry("200x250")

        Label(top, text="Escolha o tamanho da fonte:").pack(pady=10)

        for tamanho in [8, 10, 12, 14, 16, 18, 20]:
            Button(top, text=f"{tamanho}", command=lambda t=tamanho: aplicar_tamanho(t)).pack(pady=5)

    # Função para alterar as cores de fundo
    def alterar_tamanho_fonte():
        def aplicar_tamanho(tamanho):
            try:
                janela.option_add("*font", ("Arial", int(tamanho)))
                top.destroy()
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao alterar fonte: {str(e)}")

            # Altera a fonte para todos os widgets
            janela.option_add("*font", ("Arial", tamanho))
            print(f"Tamanho da fonte alterado para {tamanho}.")
            top.destroy()

        top = Toplevel(janela)
        top.title("Escolher Tamanho da Fonte")
        top.geometry("200x250")

        Label(top, text="Escolha o tamanho da fonte:").pack(pady=10)

        # Tamanhos de fonte sugeridos
        sizes = [8, 10, 12, 14, 16, 18, 20]

        for size in sizes:
            Button(
                top,
                text=f"{size} pt",
                command=lambda s=size: aplicar_tamanho(s)
            ).pack(pady=3, fill="x", padx=10)

    def resetar_aparencia():
        # Certifique-se de usar a instância Tk correta
        janela.tk_setPalette(background='#ffffff', foreground='#000000')

    """--------------------------------------------------------------------"""

    # Cria o menu de opções
    menu_bar = Menu(janela)
    janela.config(menu=menu_bar)

    # Menu Arquivo
    menu_arquivo = Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Arquivo", menu=menu_arquivo)
    menu_arquivo.add_command(label="Abrir", command=abrir_arquivo)
    menu_arquivo.add_separator()
    menu_arquivo.add_command(label="Salvar", command=salvar)

    # Menu Opções
    menu_opcoes = Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Opções", menu=menu_opcoes)
    menu_opcoes.add_command(label="Limpar Resultados", command=limpar)
    menu_opcoes.add_command(label="Verificar Links Externos", command=verificar_links)

    # Menu Informações
    menu_info = Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Info", menu=menu_info)
    menu_info.add_command(label="Sobre", command=mostrar_sobre)
    menu_info.add_command(label="Ajuda", command=mostrar_ajuda)
    menu_info.add_command(label="Versão", command=mostrar_versao)
    menu_info.add_command(label="Licença", command=mostrar_licenca)
    menu_info.add_command(label="Documentação", command=abrir_documentacao)

    # Menu Configurações
    menu_config = Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Configurações", menu=menu_config)

    # Submenu Aparência dentro de Configurações
    menu_aparencia = Menu(menu_config, tearoff=0)
    menu_config.add_cascade(label="Aparência", menu=menu_aparencia)
    menu_aparencia.add_command(label="Alterar Tema", command=alternar_tema)
    menu_aparencia.add_command(label="Alterar Tamanho da Fonte", command=alterar_tamanho_fonte)
    menu_aparencia.add_command(label="Alterar Cor de Fundo", command=alterar_cor_fundo)
    menu_aparencia.add_command(label="Redefinir Aparência", command=resetar_aparencia)

    # Loop principal da janela
    janela.mainloop()


# Função para salvar os resultados no arquivo
def salvar_resultados(txt_widget):
    conteudo = txt_widget.get("1.0", "end-1c")
    filename = asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if filename:
        with open(filename, 'w') as f:
            f.write(conteudo)
