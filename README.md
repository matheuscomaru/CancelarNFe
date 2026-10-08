# Cancelar NF-e na SEFAZ

Cancele uma Nota Fiscal Eletrônica (NF-e, modelo 55) direto no webservice da
SEFAZ, sem depender de sistema emissor. Com interface gráfica ou via terminal.

> **Aviso:** projeto comunitário, sem vínculo com a SEFAZ. O cancelamento em
> **produção tem validade jurídica e não tem volta**. Confira todos os dados
> antes de enviar. Em caso de dúvida fiscal, fale com seu contador.

---

## Para quem é

Para quem ficou sem sistema emissor mas tem em mãos:

- o **XML da NF-e autorizada** (ou chave + protocolo + CNPJ);
- o **certificado digital A1** do CNPJ emitente (arquivo `.pfx` + senha).

O programa monta o evento de cancelamento (`110111`), assina com o seu
certificado e envia ao `NFeRecepcaoEvento4` do autorizador da UF.

## O que você precisa

| Item | Detalhe |
| ---- | ------- |
| Python | 3.10 ou superior (Windows, Linux ou macOS) |
| Certificado | A1 (`.pfx`/`.p12`) do CNPJ **emitente** da nota + senha |
| Dados da nota | XML autorizado **ou** chave (44 dígitos) + protocolo (`nProt`) + CNPJ |
| Justificativa | Texto de 15 a 255 caracteres (ex.: "Nota emitida com CFOP incorreto") |
| Prazo | Regra geral: até **24h** da autorização. Várias SEFAZ aceitam até **480h** (retorno 155). Depois disso, só pedido extemporâneo no Posto Fiscal |

## Instalação

```bash
# 1. Baixe ou clone o repositório
git clone https://github.com/SEU-USUARIO/CancelarNFe.git
cd CancelarNFe

# 2. (recomendado) crie um ambiente virtual
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt
```

## Como usar — interface gráfica (recomendado)

```bash
python cancelar_gui.py
```

Passo a passo na telinha:

1. **Certificado:** clique em *Procurar* e selecione o `.pfx`; digite a senha.
2. **XML autorizado:** clique em *Procurar* e selecione o XML da NF-e.
   Chave, CNPJ, protocolo e UF são preenchidos sozinhos.
3. **Ambiente:** deixe **Produção** para valer de verdade. Use
   **Homologação** só para testes.
4. **Justificativa:** escreva o motivo (mínimo 15 caracteres).
5. Clique em **Cancelar NF-e na SEFAZ**, confira o resumo e confirme.
6. Acompanhe o resultado no quadro de log. Em caso de sucesso, guarde o
   arquivo `retEvento-cancel-*.xml` — ele é o **comprovante** do cancelamento.

## Como usar — terminal

Com o XML autorizado (ele extrai chave e CNPJ sozinho):

```bash
python cancelar_nfe.py \
  --certificado "empresa.pfx" \
  --senha "sua-senha" \
  --xml "NFe-autorizada.xml" \
  --protocolo "135250000000000" \
  --justificativa "Nota emitida com CFOP incorreto" \
  --ambiente prod
```

Passando todos os dados manualmente:

```bash
python cancelar_nfe.py \
  --certificado "empresa.pfx" \
  --senha "sua-senha" \
  --chave "35260112345678000199550010000000011000000011" \
  --cnpj "12345678000199" \
  --protocolo "135250000000000" \
  --justificativa "Nota emitida com CFOP incorreto" \
  --ambiente prod \
  --uf SP
```

Opções úteis:

| Opção | Para quê |
| ----- | -------- |
| `--ambiente homolog` | Testar sem validade fiscal |
| `--uf MG` | Forçar a UF (normalmente é detectada pela chave) |
| `--url ...` | Forçar a URL do webservice (casos especiais) |
| `--salvar-em ./saida` | Pasta onde salvar os XMLs de envio e retorno |

## Entendendo o retorno

O programa mostra o `cStat`/`xMotivo` devolvido pela SEFAZ e salva o XML de
resposta (`retEvento-cancel-*.xml`).

| cStat | Significado | O que fazer |
| ----- | ----------- | ----------- |
| 135 | Cancelamento homologado | OK. Arquive o comprovante |
| 155 | Homologado **fora de prazo** | OK (vale como denúncia espontânea em várias UFs). Ajuste a escrituração |
| 136 | Evento registrado, mas não vinculado | Verifique a situação da nota com seu contador |
| 573 | Evento duplicado | A nota provavelmente **já está cancelada**. Consulte a chave no portal da NF-e |
| 590/591 | Fora de prazo ou operação vinculada (circulação, MDF-e/CT-e, manifestação do destinatário) | Não é possível cancelar por evento. Procure o Posto Fiscal |
| 579/580 | Falha na assinatura ou certificado | Confira senha do `.pfx`, cadeia ICP-Brasil e se o certificado é do emitente |
| 404 | Prefixo de namespace não permitido | Atualize o programa (`git pull`) — versões antigas geravam prefixos que MG rejeita |
| 215 | Falha no esquema XML | Atualize o programa e confira os dados (chave, protocolo, CNPJ) |
| HTTP diferente de 200 | Erro de comunicação | Verifique internet, data/hora da máquina e se a URL do autorizador está acessível |

> Dica: antes de cancelar em produção, faça um teste em **homologação**
> para validar certificado e conectividade.

## Como funciona (resumo técnico)

1. Monta o `envEvento` do evento `110111` (NT 2011/006), com `cOrgao`
   derivado da chave e `dhEvento` atual (UTC-3).
2. Assina o `infEvento` em XMLDSig enveloped, RSA-SHA1 + SHA-1 + C14N 1.0,
   exatamente no padrão do MOC: sem prefixos de namespace e com a
   `<Signature>` como filha de `<evento>`.
3. Envia via mTLS (certificado cliente) em envelope SOAP 1.2 ao
   `NFeRecepcaoEvento4` do autorizador da UF (tabela embutida: SEFAZ
   próprias, SVRS e SVAN — fonte: portal DFe da SVRS).
4. Interpreta o `retEnvEvento` e classifica o resultado (135/136/155 = OK).

## Estrutura do projeto

```
CancelarNFe/
├── cancelar_gui.py   # interface gráfica (Tkinter, sem dependência extra)
├── cancelar_nfe.py   # lógica + CLI (monta, assina e envia o evento)
├── requirements.txt  # lxml, cryptography, requests
├── .gitignore        # bloqueia .pfx, .pem e XMLs com dados reais
└── README.md
```

## Segurança

- **Nunca** commite `.pfx`, `.p12`, `.pem`, senhas ou XMLs com dados reais.
  O `.gitignore` já bloqueia esses arquivos — confira com
  `git status` antes de cada commit.
- Rode em máquina de confiança e apague os arquivos locais após concluir.
- O certificado representa a sua empresa: não compartilhe o `.pfx` nem a senha.

## Contribuindo

Encontrou um erro ou uma SEFAZ com comportamento diferente? Abra uma
*issue* informando UF, `cStat`/`xMotivo` recebidos (sem dados sensíveis) ou
mande um *pull request*. Ajuda com testes em outras UFs é bem-vinda.

## Licença

Sugestão: distribuir sob a licença **MIT** (adicione um arquivo `LICENSE`
com o texto da licença). Até lá, todos os direitos reservados ao autor.
