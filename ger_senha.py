import os
import json
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Diretório do pendrive/executável
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SALT_FILE = os.path.join(BASE_DIR, "salt.bin")
DATA_FILE = os.path.join(BASE_DIR, "senhas.enc")

def gerar_chave_de_senha(senha_mestra, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(senha_mestra.encode()))
    return key

def inicializar_cofre():
    # Se não existe o arquivo de dados, é o primeiro uso (criar senha mestra)
    if not os.path.exists(DATA_FILE):
        senha1 = simpledialog.askstring("Primeiro Uso", "Crie uma Senha Mestra para o seu pendrive:", show="*")
        if not senha1:
            return None, None
        senha2 = simpledialog.askstring("Primeiro Uso", "Confirme a Senha Mestra:", show="*")
        if senha1 != senha2:
            messagebox.showerror("Erro", "As senhas não coincidem.")
            return None, None
        
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
            
        key = gerar_chave_de_senha(senha1, salt)
        # Salva um cofre vazio inicial
        dados_iniciais = {}
        dados_json = json.dumps(dados_iniciais).encode()
        cipher = Fernet(key)
        with open(DATA_FILE, "wb") as f:
            f.write(cipher.encrypt(dados_json))
        
        messagebox.showinfo("Sucesso", "Cofre criado com sucesso!")
        return key, dados_iniciais

    # Se já existe, pede a senha mestra para desbloquear
    senha = simpledialog.askstring("Desbloquear", "Digite sua Senha Mestra:", show="*")
    if not senha:
        return None, None

    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        
        key = gerar_chave_de_senha(senha, salt)
        cipher = Fernet(key)

        with open(DATA_FILE, "rb") as f:
            dados_cifrados = f.read()
        
        dados_decifrados = cipher.decrypt(dados_cifrados)
        return key, json.loads(dados_decifrados.decode())
    except Exception:
        messagebox.showerror("Erro", "Senha Mestra incorreta ou dados corrompidos.")
        return None, None

def salvar_dados(dados, key):
    cipher = Fernet(key)
    dados_json = json.dumps(dados).encode()
    dados_cifrados = cipher.encrypt(dados_json)
    with open(DATA_FILE, "wb") as f:
        f.write(dados_cifrados)

class AppGerenciador:
    def __init__(self, root, key, dados):
        self.root = root
        self.key = key
        self.dados = dados
        
        self.root.title("Cofre Portátil de Senhas")
        self.root.geometry("450x350")

        lbl_titulo = tk.Label(root, text="Suas Senhas Seguras (Pendrive)", font=("Arial", 12, "bold"))
        lbl_titulo.pack(pady=10)

        self.tree = ttk.Treeview(root, columns=("Serviço", "Usuário"), show="headings", height=8)
        self.tree.heading("Serviço", text="Serviço / Site")
        self.tree.heading("Usuário", text="Usuário / E-mail")
        self.tree.column("Serviço", width=180)
        self.tree.column("Usuário", width=180)
        self.tree.pack(pady=5)
        self.tree.bind("<Double-1>", self.copiar_senha_evento)

        frame_botoes = tk.Frame(root)
        frame_botoes.pack(pady=10)

        btn_copiar = tk.Button(frame_botoes, text="Copiar Senha", command=self.copiar_senha, bg="#d4edda", width=15)
        btn_copiar.grid(row=0, column=0, padx=5)

        btn_adicionar = tk.Button(frame_botoes, text="Nova Senha", command=self.adicionar_senha, bg="#cce5ff", width=15)
        btn_adicionar.grid(row=0, column=1, padx=5)

        btn_mudar_senha = tk.Button(frame_botoes, text="Mudar Senha", command=self.alterar_senha_mestra, bg="#fff3cd", width=12)
        btn_mudar_senha.grid(row=0, column=3, padx=5)

        btn_deletar = tk.Button(frame_botoes, text="Excluir", command=self.deletar_senha, bg="#f8d7da", width=10)
        btn_deletar.grid(row=0, column=2, padx=5)

        self.atualizar_lista()

    def atualizar_lista(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for servico, info in self.dados.items():
            self.tree.insert("", "end", values=(servico, info["usuario"]))

    def copiar_senha(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Selecione um item da lista.")
            return
        item = self.tree.item(selected)
        servico = item["values"][0]
        senha = self.dados[servico]["senha"]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(senha)
        messagebox.showinfo("Sucesso", f"A senha para '{servico}' foi copiada!")

    def copiar_senha_evento(self, event):
        self.copiar_senha()

    def adicionar_senha(self):
        servico = simpledialog.askstring("Novo", "Nome do Serviço (ex: Gmail, Banco):")
        if not servico: return
        usuario = simpledialog.askstring("Novo", "Usuário ou E-mail:")
        if not usuario: return
        senha = simpledialog.askstring("Novo", "Senha:", show="*")
        if not senha: return

        self.dados[servico] = {"usuario": usuario, "senha": senha}
        salvar_dados(self.dados, self.key)
        self.atualizar_lista()
        messagebox.showinfo("Sucesso", "Senha salva com sucesso no pendrive!")
    
    def alterar_senha_mestra(self):
        # Pede a nova senha e a confirmação
        nova_senha1 = simpledialog.askstring("Alterar Senha", "Digite a nova Senha Mestra:", show="*")
        if not nova_senha1: 
            return
        
        nova_senha2 = simpledialog.askstring("Alterar Senha", "Confirme a nova Senha Mestra:", show="*")
        if nova_senha1 != nova_senha2:
            messagebox.showerror("Erro", "As senhas não coincidem.")
            return

        # Gera um novo salt e uma nova chave baseada na nova senha
        novo_salt = os.urandom(16)
        nova_chave = gerar_chave_de_senha(nova_senha1, novo_salt)

        try:
            # Salva o novo salt
            with open(SALT_FILE, "wb") as f:
                f.write(novo_salt)

            # Atualiza a chave da aplicação e salva os dados existentes com a nova chave
            self.key = nova_chave
            salvar_dados(self.dados, self.key)

            messagebox.showinfo("Sucesso", "Senha Mestra alterada com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível alterar a senha: {e}")

    def deletar_senha(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Selecione um item para excluir.")
            return
        item = self.tree.item(selected)
        servico = item["values"][0]
        
        if messagebox.askyesno("Confirmar", f"Deseja excluir a senha de '{servico}'?"):
            del self.dados[servico]
            salvar_dados(self.dados, self.key)
            self.atualizar_lista()

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() # Esconde a janela principal temporariamente enquanto pede a senha
    
    KEY, dados = inicializar_cofre()
    
    if KEY is not None and dados is not None:
        root.deiconify() # Mostra a janela principal após autenticar
        app = AppGerenciador(root, KEY, dados)
        root.mainloop()
    else:
        root.destroy()