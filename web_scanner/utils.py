def adicionar_https(event, entry_widget):
    url = entry_widget.get()
    if not url.startswith("https://") and not url.startswith("http://"):
        entry_widget.insert(0, "https://")


def limpar_resultados(txt_widget):
    txt_widget.delete('1.0', 'end')
