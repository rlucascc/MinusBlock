from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
import os
import tkinter as tk
from tkinter import filedialog, messagebox


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # JANELA PRINCIPAL
        self.title('MinusBlock')
        self.geometry('500x500')
        self.resizable(width=False, height=False)

        # ARQUIVO E DIRETÓRIO PARA ENCRIPTAÇÃO E DECRIPTAÇÃO
        self.__filepath = None
        self.__dirpath  = None
        self.__file_2FA = None

        self.__filepath_decrip = None
        self.__file_2FA_decrip = None

        # SENHAS PARA CRIAÇÃO DE HASH
        self.__password = None
        self.__password_confirm = None
        self.__password_dcrip = None

        # FRAME DE ENCRIPTAÇÃO -----------------------------------------------------------------------------------------
        self.frame_encript = tk.Frame(self, width=490, height=240, borderwidth=1, relief='solid')
        self.frame_encript.place(x=5, y=5)

        self.var_file = tk.StringVar()
        self.var_dir = tk.StringVar()
        self.var_pass = tk.StringVar()
        self.var_pass_confirm = tk.StringVar()

        self.label_entry_encript1 = tk.Label(self.frame_encript,
                                            text='Arquivo de entrada: ',
                                            font=('roboto', 12, 'italic')).place(x=10, y=10)

        self.label_entry_encript2 = tk.Label(self.frame_encript,
                                            text='Diretório final: ',
                                            font=('roboto', 12, 'italic')).place(x=10, y=40)


        self.entry_file = tk.Entry(self.frame_encript,
                                   textvariable=self.var_file,
                                   font=('roboto', 10, 'italic')).place(x=170, y=10)

        self.entry_dir = tk.Entry(self.frame_encript,
                                  textvariable=self.var_dir,
                                  font=('roboto', 10, 'italic')).place(x=170, y=40)

        self.btn_crip_fp = tk.Button(self.frame_encript, text='...', command=self.escolher_arquivo).place(x=350, y=7)
        self.btn_crip_dp = tk.Button(self.frame_encript, text='...', command=self.escolher_dir).place(x=350, y=37)

        self.label_pass_cript = tk.Label(self.frame_encript, text='Digite a senha: ', font=('roboto', 12, 'italic')).place(x=10, y=110)
        self.label_passconfirm_cript = tk.Label(self.frame_encript, text='Conmfirme a senha: ', font=('roboto', 12, 'italic')).place(x=10, y=140)

        self.entry_pass = tk.Entry(self.frame_encript,
                                  textvariable=self.var_pass,
                                  font=('roboto', 10, 'italic'),
                                  show='*').place(x=170, y=110)

        self.entry_pass_comfirm = tk.Entry(self.frame_encript,
                                   textvariable=self.var_pass_confirm,
                                   font=('roboto', 10, 'italic'),
                                   show='*').place(x=170, y=140)

        self.btn_arquivo_cript = tk.Button(self.frame_encript, text='ARQUIVO\n2FA', command=self.escolher_arquivo_2FA).place(x=350, y=115)

        self.btn_encript= tk.Button(self.frame_encript, text='ENCRIPTAR', command=self.criar_hash_encrip).place(x=205, y=190)


        # FRAME DE DECRIPTAÇÃO -----------------------------------------------------------------------------------------
        self.frame_decript = tk.Frame(self, width=490, height=240, borderwidth=1, relief='solid')
        self.frame_decript.place(x=5, y=250)

        self.var_file_dcrip = tk.StringVar()
        self.var_pass_dcrip = tk.StringVar()

        self.entry_file_dcrip = tk.Entry(self.frame_decript,
                                         textvariable=self.var_file_dcrip,
                                         font=('roboto', 10, 'italic')).place(x=170, y=10)

        self.label_dcrip1 = tk.Label(self.frame_decript,
                                     text='Arquivo de entrada: ',
                                     font=('roboto', 12, 'italic')).place(x=10, y=10)

        self.entry_pass_dcrip = tk.Entry(self.frame_decript,
                                         textvariable=self.var_pass_dcrip,
                                         font=('roboto', 10, 'italic'),
                                         show='*').place(x=170, y=80)

        self.label_dcrip2 = tk.Label(self.frame_decript,
                                         text='Digite a senha: ',
                                         font=('roboto', 12, 'italic')).place(x=10, y=80)

        self.btn_dcrip_fp = tk.Button(self.frame_decript, text='...', command=self.escolher_arquivo_decrip).place(x=350, y=7)

        self.btn_arquivo_dcrip = tk.Button(self.frame_decript, text='ARQUIVO\n2FA', command=self.escolher_arquivo_2FA_decrip).place(x=350, y=70)


        self.btn_decript = tk.Button(self.frame_decript, text='DECRIPTAR', command=self.criar_hash_decrip).place(x=205, y=190)



    def escolher_arquivo(self):
        self.__filepath = filedialog.askopenfilename()
        self.var_file.set(self.__filepath)

    def escolher_arquivo_decrip(self):
        self.__filepath_decrip = filedialog.askopenfilename()
        self.var_file_dcrip.set(self.__filepath_decrip)

    def escolher_dir(self):
        self.__dirpath = filedialog.askdirectory()
        self.var_dir.set(self.__dirpath)

    def escolher_arquivo_2FA(self):
        self.__file_2FA = filedialog.askopenfilename()
        if(self.__file_2FA == () or self.__file_2FA == None):
            messagebox.showerror(title='ARQUIVO NÃO ESCOLHIDO', message='Erro na escolha do arquivo.')
        else:
            messagebox.showinfo(title='ARQUIVO ESCOLHIDO', message=self.__file_2FA)

    def escolher_arquivo_2FA_decrip(self):
        self.__file_2FA_decrip = filedialog.askopenfilename()
        if(self.__file_2FA_decrip == () or self.__file_2FA_decrip == None):
            messagebox.showerror(title='ARQUIVO NÃO ESCOLHIDO', message='Erro na escolha do arquivo.')
        else:
            messagebox.showinfo(title='ARQUIVO ESCOLHIDO', message=self.__file_2FA_decrip)


    def criar_hash_encrip(self):
        self.__password = self.var_pass.get()
        self.__password_confirm = self.var_pass_confirm.get()
        if(self.__password == self.__password_confirm and (self.__file_2FA != None and self.__file_2FA != ())):
            if((self.__filepath != None and self.__filepath != ()) and ((self.__dirpath != None and self.__dirpath != ()))):
                try:
                    md5_user = md5()
                    md5_user.update(self.__password.encode('utf-8'))
                    half_user = md5_user.hexdigest()

                    md5_file = md5()
                    with open(self.__file_2FA, 'rb') as a:
                        bin_file = a.read()

                    md5_file.update(bin_file)
                    half_file = md5_file.hexdigest()

                    return half_user[16:] + half_file[:16]
                except Exception as e:
                    messagebox.showerror(title='FATAL ERROR' ,message=f'{e}')
            else:
                messagebox.showerror(title='ERRO',message='Erro na tentativa de encriptação.\nVerifique o arquivo ou o diretório escolhidos.')
        else:
            messagebox.showerror(title='ERRO', message='Erro na tentativa de encriptação.\nVerifique a senha ou o arquivo 2FA escolhido.')

    def criar_hash_decrip(self):
        self.__password_dcrip = self.var_pass_dcrip.get()
        if(self.__password_dcrip != None and (self.__file_2FA_decrip != None and self.__file_2FA_decrip != ())):
            if(self.__filepath_decrip != None and self.__filepath_decrip != ()):
                try:
                    md5_user = md5()
                    md5_user.update(self.__password_dcrip.encode('utf-8'))
                    half_user = md5_user.hexdigest()

                    md5_file = md5()
                    with open(self.__file_2FA_decrip, 'rb') as a:
                        bin_file = a.read()

                    md5_file.update(bin_file)
                    half_file = md5_file.hexdigest()

                    return print(half_user[16:] + half_file[:16])
                except Exception as e:
                    messagebox.showerror(title='FATAL ERROR', message=f'{e}')
            else:
                messagebox.showerror(title='ERRO',message='Erro na tentativa de decriptação.\nVerifique o arquivo escolhido.')
        else:
            messagebox.showerror(title='ERRO', message='Erro na tentativa decriptação.\nVerifique a senha ou o arquivo 2FA escolhido.')

    def encryptar_arquivo(self, input, output, senha_final):
        salt = os.urandom(16)
        chave_PBKDF2 = PBKDF2(senha_final.encode(), salt, dkLen=32)

        cifra_AES = AES.new(chave_PBKDF2, AES.MODE_CBC)
        vetor = cifra_AES.iv

        with open(input, 'rb') as arquivo:
            texto_bin = arquivo.read()

        arquivo_encriptado = cifra_AES.encrypt(pad(texto_bin, AES.block_size))

        with open(output, 'wb') as f:
            f.write(salt + vetor + arquivo_encriptado)


    def decriptar_arquivo(self, input, senha_final):
        with open(input, 'rb') as arquivo:
            salt = arquivo.read(16)
            vetor = arquivo.read(16)
            texto_encriptado = arquivo.read()

        chave_PBKDF2 = PBKDF2(senha_final.encode(), salt, dkLen=32)

        cifra_AES = AES.new(chave_PBKDF2, AES.MODE_CBC, vetor)
        arquivo_decriptografado = unpad(cifra_AES.decrypt(texto_encriptado), AES.block_size)

        with open(input, 'wb') as f:
            f.write(arquivo_decriptografado)

if __name__ == '__main__':
    app = MainApp()
    app.mainloop()
