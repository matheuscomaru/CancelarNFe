#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telinha para cancelar NF-e (evento 110111) sem usar terminal.

Execução:
    py cancelar_gui.py

Reaproveita toda a lógica de cancelar_nfe.py (assinatura + envio SOAP).
"""

from __future__ import annotations

import queue
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import requests
from cryptography.hazmat.primitives import serialization
from lxml import etree

import cancelar_nfe as core


UFS = ["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
       "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
       "RS", "RO", "RR", "SC", "SP", "SE", "TO"]


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cancelar NF-e — SEFAZ")
        self.geometry("640x720")
        self.minsize(600, 680)
        self.log_queue: queue.Queue[str] = queue.Queue()
        self._build()
        self.after(150, self._drain_log)

    # ---------------- layout ----------------
    def _build(self) -> None:
        pad = {"padx": 8, "pady": 3}
        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Certificado
        ttk.Label(frm, text="Certificado A1 (.pfx/.p12)").grid(row=0, column=0, sticky="w", **pad)
        self.var_pfx = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var_pfx, width=52).grid(row=1, column=0, sticky="ew", **pad)
        ttk.Button(frm, text="Procurar…", command=self._pick_pfx).grid(row=1, column=1, **pad)

        ttk.Label(frm, text="Senha do certificado").grid(row=2, column=0, sticky="w", **pad)
        self.var_senha = tk.StringVar()
        self.ent_senha = ttk.Entry(frm, textvariable=self.var_senha, show="•", width=52)
        self.ent_senha.grid(row=3, column=0, sticky="ew", **pad)
        self.var_mostrar = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="mostrar", variable=self.var_mostrar,
                        command=self._toggle_senha).grid(row=3, column=1, **pad)

        # XML autorizado
        ttk.Label(frm, text="XML autorizado (opcional — preenche chave/CNPJ/protocolo)").grid(
            row=4, column=0, sticky="w", **pad)
        self.var_xml = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var_xml, width=52).grid(row=5, column=0, sticky="ew", **pad)
        ttk.Button(frm, text="Procurar…", command=self._pick_xml).grid(row=5, column=1, **pad)

        # Chave / CNPJ / protocolo
        ttk.Label(frm, text="Chave de acesso (44 dígitos)").grid(row=6, column=0, sticky="w", **pad)
        self.var_chave = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var_chave).grid(row=7, column=0, columnspan=2, sticky="ew", **pad)

        row = ttk.Frame(frm)
        row.grid(row=8, column=0, columnspan=2, sticky="ew")
        row.columnconfigure((0, 1, 2), weight=1)
        ttk.Label(row, text="CNPJ emitente").grid(row=0, column=0, sticky="w", padx=8)
        ttk.Label(row, text="Protocolo (nProt)").grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(row, text="UF").grid(row=0, column=2, sticky="w", padx=8)
        self.var_cnpj = tk.StringVar()
        self.var_prot = tk.StringVar()
        self.var_uf = tk.StringVar()
        ttk.Entry(row, textvariable=self.var_cnpj).grid(row=1, column=0, sticky="ew", padx=8)
        ttk.Entry(row, textvariable=self.var_prot).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Combobox(row, textvariable=self.var_uf, values=["(auto)"] + UFS,
                     width=10, state="readonly").grid(row=1, column=2, sticky="ew", padx=8)
        self.var_uf.set("(auto)")

        # Ambiente
        amb = ttk.Frame(frm)
        amb.grid(row=9, column=0, columnspan=2, sticky="w", **pad)
        ttk.Label(amb, text="Ambiente:").pack(side=tk.LEFT)
        self.var_amb = tk.StringVar(value="prod")
        ttk.Radiobutton(amb, text="Produção (vale de verdade)", variable=self.var_amb,
                        value="prod").pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(amb, text="Homologação (teste)", variable=self.var_amb,
                        value="homolog").pack(side=tk.LEFT)

        # Justificativa
        ttk.Label(frm, text="Justificativa (mín. 15 caracteres)").grid(row=10, column=0, sticky="w", **pad)
        self.lbl_cont = ttk.Label(frm, text="0 caracteres")
        self.lbl_cont.grid(row=10, column=1, sticky="e", **pad)
        self.txt_just = tk.Text(frm, height=3, wrap=tk.WORD)
        self.txt_just.grid(row=11, column=0, columnspan=2, sticky="ew", **pad)
        self.txt_just.bind("<<Modified>>", self._contar)
        self.txt_just.edit_modified(False)

        # Ações
        btns = ttk.Frame(frm)
        btns.grid(row=12, column=0, columnspan=2, pady=10)
        self.btn_enviar = ttk.Button(btns, text="Cancelar NF-e na SEFAZ", command=self._confirmar_enviar)
        self.btn_enviar.pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Limpar", command=self._limpar).pack(side=tk.LEFT, padx=5)

        # Log
        ttk.Label(frm, text="Retorno").grid(row=13, column=0, sticky="w", **pad)
        self.log = scrolledtext.ScrolledText(frm, height=12, state=tk.DISABLED)
        self.log.grid(row=14, column=0, columnspan=2, sticky="nsew", **pad)
        frm.rowconfigure(14, weight=1)
        frm.columnconfigure(0, weight=1)

    # ---------------- helpers ----------------
    def _pick_pfx(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("Certificado", "*.pfx *.p12"), ("Todos", "*.*")])
        if p:
            self.var_pfx.set(p)

    def _pick_xml(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("XML NFe", "*.xml"), ("Todos", "*.*")])
        if not p:
            return
        self.var_xml.set(p)
        try:
            dados = core.extrair_dados_do_xml(Path(p))
        except Exception as e:
            messagebox.showerror("XML inválido", f"Não consegui ler o XML:\n{e}")
            return
        if dados.get("chave"):
            self.var_chave.set(dados["chave"])
        if dados.get("cnpj"):
            self.var_cnpj.set(dados["cnpj"])
        if dados.get("protocolo"):
            self.var_prot.set(dados["protocolo"])
        chave = dados.get("chave", "")
        if len(chave) >= 2:
            uf = core.COD_IBGE_UF.get(chave[:2], "")
            if uf:
                self.var_uf.set(uf)
        self._log(f"XML lido: chave={dados.get('chave', '?')[:10]}… "
                  f"cnpj={dados.get('cnpj', '?')} protocolo={dados.get('protocolo', '?')}")

    def _toggle_senha(self) -> None:
        self.ent_senha.config(show="" if self.var_mostrar.get() else "•")

    def _contar(self, _evt=None) -> None:
        n = len(self.txt_just.get("1.0", tk.END).strip())
        self.lbl_cont.config(text=f"{n} caracteres")
        self.txt_just.edit_modified(False)

    def _limpar(self) -> None:
        for v in (self.var_pfx, self.var_senha, self.var_xml, self.var_chave,
                  self.var_cnpj, self.var_prot):
            v.set("")
        self.var_uf.set("(auto)")
        self.var_amb.set("prod")
        self.txt_just.delete("1.0", tk.END)
        self._contar()

    def _log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _drain_log(self) -> None:
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log.config(state=tk.NORMAL)
            self.log.insert(tk.END, msg + "\n")
            self.log.see(tk.END)
            self.log.config(state=tk.DISABLED)
        self.after(150, self._drain_log)

    # ---------------- envio ----------------
    def _confirmar_enviar(self) -> None:
        just = self.txt_just.get("1.0", tk.END).strip()
        try:
            core.validar_entradas(self.var_chave.get().strip(),
                                  core.somente_digitos(self.var_cnpj.get()),
                                  self.var_prot.get().strip(), just)
        except ValueError as e:
            messagebox.showerror("Verifique os dados", str(e))
            return
        if not Path(self.var_pfx.get()).is_file():
            messagebox.showerror("Verifique os dados", "Selecione o certificado .pfx.")
            return
        if self.var_amb.get() == "prod":
            ok = messagebox.askyesno(
                "Confirmar cancelamento",
                "AMBIENTE DE PRODUÇÃO: o cancelamento vale de verdade e não tem volta.\n\n"
                f"Chave: {self.var_chave.get().strip()}\n"
                f"Confirma o envio para a SEFAZ?")
            if not ok:
                return
        self.btn_enviar.config(state=tk.DISABLED)
        threading.Thread(target=self._enviar, daemon=True).start()

    def _enviar(self) -> None:
        try:
            pfx = Path(self.var_pfx.get())
            senha = self.var_senha.get()
            chave = core.somente_digitos(self.var_chave.get())
            cnpj = core.somente_digitos(self.var_cnpj.get())
            prot = self.var_prot.get().strip()
            just = self.txt_just.get("1.0", tk.END).strip()
            uf = self.var_uf.get()
            uf = None if uf == "(auto)" else uf
            ambiente = self.var_amb.get()

            self._log("Lendo certificado…")
            key, cert, chain = core.carregar_pfx(pfx, senha)

            url, uf_final, aut = core.resolver_url(uf, chave, ambiente, None)
            self._log(f"UF={uf_final} autorizador={aut} ambiente={ambiente}")
            self._log(f"URL={url}")

            c_orgao, tp_amb = chave[:2], ("1" if ambiente == "prod" else "2")
            env = core.montar_env_evento(chave, cnpj, c_orgao, tp_amb, prot, just)
            self._log("Assinando evento…")
            signed = core.assinar_inf_evento(env, key, cert, chain)
            out = Path(".")
            envio = out / f"envEvento-cancel-{chave}.xml"
            envio.write_bytes(etree.tostring(signed, xml_declaration=True, encoding="utf-8"))
            self._log(f"XML assinado salvo: {envio}")
            soap = core.envelopar_soap(signed)

            tc = tempfile.NamedTemporaryFile(delete=False, suffix="-cert.pem")
            tkf = tempfile.NamedTemporaryFile(delete=False, suffix="-key.pem")
            try:
                for c in [cert, *chain]:
                    tc.write(c.public_bytes(serialization.Encoding.PEM))
                self._log(f"Cadeia do certificado: {1 + len(chain)} certificado(s)")
                tc.close()
                tkf.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                tkf.close()
                self._log("Enviando para a SEFAZ…")
                resp = requests.post(
                    url, data=soap,
                    headers={"Content-Type":
                             f'application/soap+xml; charset=utf-8; action="{core.SOAP_ACTION}"'},
                    cert=(tc.name, tkf.name), verify=core.ca_bundle(), timeout=30)
            finally:
                Path(tc.name).unlink(missing_ok=True)
                Path(tkf.name).unlink(missing_ok=True)

            ret_path = out / f"retEvento-cancel-{chave}.xml"
            ret_path.write_bytes(resp.content)
            self._log(f"HTTP {resp.status_code} — resposta salva: {ret_path}")
            ret = core.interpretar_retorno(resp.content)
            self._log(f"cStat={ret['cStat']} xMotivo={ret['xMotivo']}")
            if ret["cStat"] in core.CSTAT_SUCESSO:
                self._log("✅ Cancelamento homologado pela SEFAZ.")
                messagebox.showinfo("Pronto",
                                    f"Cancelamento homologado.\ncStat={ret['cStat']}\n{ret['xMotivo']}")
            else:
                self._log(f"❌ Não homologado: {ret['xMotivo']}")
                messagebox.showerror("Não homologado",
                                     f"cStat={ret['cStat']}\n{ret['xMotivo']}")
        except Exception as e:  # noqa: BLE001 — mostra qualquer erro na telinha
            self._log(f"[erro] {e}")
            messagebox.showerror("Erro", str(e))
        finally:
            self.btn_enviar.config(state=tk.NORMAL)


if __name__ == "__main__":
    App().mainloop()
