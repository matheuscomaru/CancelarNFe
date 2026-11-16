#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cancelamento de NF-e via WebService NFeRecepcaoEvento4 (evento 110111).

Uso típico (produção):
    python cancelar_nfe.py ^
        --certificado "C:\\certs\\empresa.pfx" ^
        --senha "senha-do-pfx" ^
        --xml "NFe-autorizada.xml" ^
        --protocolo "135250000000000" ^
        --justificativa "Cancelamento por erro de digitacao do CFOP" ^
        --ambiente prod

Você também pode passar tudo manualmente:
    python cancelar_nfe.py --certificado emp.pfx --senha xxx ^
        --chave 352608... --cnpj 12345678000199 --protocolo 135... ^
        --justificativa "Motivo com no minimo 15 caracteres" --ambiente prod --uf SP

Retorno de sucesso da SEFAZ:
    cStat 135 = Evento registrado e vinculado (cancelamento homologado)
    cStat 136 = Evento registrado, mas não vinculado (verificar)
    cStat 155 = Cancelamento homologado fora de prazo (algumas SEFAZ)
Qualquer outro cStat = erro (veja xMotivo impresso).

Requisitos: pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import tempfile
from pathlib import Path

import certifi
import requests
from cryptography import x509


def ca_bundle() -> str:
    """Bundle certifi + raízes ICP-Brasil (pasta certs/), usada pelas SEFAZ."""
    out = Path(tempfile.gettempdir()) / "cancelarnfe-ca-bundle.pem"
    pem = Path(certifi.where()).read_bytes()
    for f in sorted((Path(__file__).parent / "certs").glob("*.crt")):
        data = f.read_bytes()
        if b"-----BEGIN" not in data:
            data = x509.load_der_x509_certificate(data).public_bytes(serialization.Encoding.PEM)
        pem += b"\n" + data
    out.write_bytes(pem)
    return str(out)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from lxml import etree

# ---------------------------------------------------------------------------
# URLs RecepcaoEvento 4.00 por autorizador (fonte: dfe-portal.svrs.rs.gov.br/NFE/Servicos)
# ---------------------------------------------------------------------------
URLS_PROD = {
    "AM": "https://nfe.sefaz.am.gov.br/services2/services/RecepcaoEvento4",
    "BA": "https://nfe.sefaz.ba.gov.br/webservices/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
    "GO": "https://nfe.sefaz.go.gov.br/nfe/services/NFeRecepcaoEvento4",
    "MG": "https://nfe.fazenda.mg.gov.br/nfe2/services/NFeRecepcaoEvento4",
    "MS": "https://nfe.sefaz.ms.gov.br/ws/NFeRecepcaoEvento4",
    "MT": "https://nfe.sefaz.mt.gov.br/nfews/v2/services/RecepcaoEvento4",
    "PE": "https://nfe.sefaz.pe.gov.br/nfe-service/services/NFeRecepcaoEvento4",
    "PR": "https://nfe.sefa.pr.gov.br/nfe/NFeRecepcaoEvento4",
    "RS": "https://nfe.sefazrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx",
    "SP": "https://nfe.fazenda.sp.gov.br/ws/nferecepcaoevento4.asmx",
    "SVAN": "https://www.sefazvirtual.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
    "SVRS": "https://nfe.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx",
    "AN": "https://www.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
}

URLS_HOMOLOG = {
    "AM": "https://homnfe.sefaz.am.gov.br/services2/services/RecepcaoEvento4",
    "BA": "https://hnfe.sefaz.ba.gov.br/webservices/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
    "GO": "https://homolog.sefaz.go.gov.br/nfe/services/NFeRecepcaoEvento4",
    "MG": "https://hnfe.fazenda.mg.gov.br/nfe2/services/NFeRecepcaoEvento4",
    "MS": "https://hom.nfe.sefaz.ms.gov.br/ws/NFeRecepcaoEvento4",
    "MT": "https://homologacao.sefaz.mt.gov.br/nfews/v2/services/RecepcaoEvento4",
    "PE": "https://nfehomolog.sefaz.pe.gov.br/nfe-service/services/NFeRecepcaoEvento4",
    "PR": "https://homologacao.nfe.sefa.pr.gov.br/nfe/NFeRecepcaoEvento4",
    "RS": "https://nfe-homologacao.sefazrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx",
    "SP": "https://homologacao.nfe.fazenda.sp.gov.br/ws/nferecepcaoevento4.asmx",
    "SVAN": "https://hom.sefazvirtual.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
    "SVRS": "https://nfe-homologacao.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento4.asmx",
    "AN": "https://hom.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
}

# UF -> autorizador (NFe modelo 55). UFs com SEFAZ própria usam URL própria,
# demais usam SVRS, exceto MA que usa SVAN.
UF_AUTORIZADOR = {
    "AM": "AM", "BA": "BA", "GO": "GO", "MG": "MG", "MS": "MS",
    "MT": "MT", "PE": "PE", "PR": "PR", "RS": "RS", "SP": "SP",
    "MA": "SVAN",
    "AC": "SVRS", "AL": "SVRS", "AP": "SVRS", "CE": "SVRS", "DF": "SVRS",
    "ES": "SVRS", "PA": "SVRS", "PB": "SVRS", "PI": "SVRS", "RJ": "SVRS",
    "RN": "SVRS", "RO": "SVRS", "RR": "SVRS", "SC": "SVRS", "SE": "SVRS",
    "TO": "SVRS",
}

COD_IBGE_UF = {
    "11": "RO", "12": "AC", "13": "AM", "14": "RR", "15": "PA", "16": "AP",
    "17": "TO", "21": "MA", "22": "PI", "23": "CE", "24": "RN", "25": "PB",
    "26": "PE", "27": "AL", "28": "SE", "29": "BA", "31": "MG", "32": "ES",
    "33": "RJ", "35": "SP", "41": "PR", "42": "SC", "43": "RS", "50": "MS",
    "51": "MT", "52": "GO", "53": "DF",
}

SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento"
NS_NFE = "http://www.portalfiscal.inf.br/nfe"
NS_WS = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4"

CSTAT_SUCESSO = {"135", "136", "155"}


def somente_digitos(s: str | None) -> str:
    return re.sub(r"\D", "", s or "")


def extrair_dados_do_xml(xml_path: Path) -> dict:
    """Tenta extrair chave, CNPJ do emitente e protocolo de uma NFe autorizada (nfeProc)."""
    dados: dict = {}
    tree = etree.parse(str(xml_path))
    root = tree.getroot()
    ns = {"nfe": NS_NFE}

    # infNFe Id="NFe<chave>"
    inf = root.find(".//nfe:infNFe", ns)
    if inf is not None:
        _id = inf.get("Id", "")
        m = re.search(r"(\d{44})", _id)
        if m:
            dados["chave"] = m.group(1)
        emit_cnpj = root.find(".//nfe:emit/nfe:CNPJ", ns)
        if emit_cnpj is not None and emit_cnpj.text:
            dados["cnpj"] = somente_digitos(emit_cnpj.text)

    # protocolo: protNFe/infProt/nProt (ou infProt direto)
    nprot = root.find(".//nfe:infProt/nfe:nProt", ns)
    if nprot is not None and nprot.text:
        dados["protocolo"] = nprot.text.strip()

    # fallback: chave pode estar em <chNFe>
    if "chave" not in dados:
        ch = root.find(".//nfe:chNFe", ns)
        if ch is not None and ch.text:
            dados["chave"] = somente_digitos(ch.text)

    return dados


def validar_entradas(chave: str, cnpj: str, protocolo: str, justificativa: str) -> None:
    erros = []
    if not re.fullmatch(r"\d{44}", chave):
        erros.append("chave deve ter 44 dígitos numéricos.")
    if not re.fullmatch(r"\d{14}", cnpj):
        erros.append("CNPJ deve ter 14 dígitos (só números).")
    if not re.fullmatch(r"\d{10,15}", protocolo or ""):
        erros.append("protocolo de autorização deve ser numérico (ex.: 135250000000000).")
    just = (justificativa or "").strip()
    if len(just) < 15:
        erros.append("justificativa precisa de no mínimo 15 caracteres.")
    if len(just) > 255:
        erros.append("justificativa pode ter no máximo 255 caracteres.")
    if erros:
        raise ValueError(" ".join(erros))


def carregar_pfx(pfx_path: Path, senha: str):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()
    key, cert, chain = pkcs12.load_key_and_certificates(
        pfx_data, senha.encode("utf-8") if senha else None
    )
    if key is None or cert is None:
        raise ValueError("Não foi possível ler chave/certificado do .pfx (senha incorreta?).")
    return key, cert, chain or []


def montar_env_evento(chave: str, cnpj: str, c_orgao: str, tp_amb: str,
                      protocolo: str, justificativa: str,
                      n_seq: int = 1, id_lote: int = 1) -> etree._Element:
    # Offset fixo -03:00 (evita dependência de tzdata no Windows)
    dh = datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=-3))
    ).isoformat(timespec="seconds")
    evento_id = f"ID110111{chave}{n_seq:02d}"

    # Usa namespace default (xmlns="http://www.portalfiscal.inf.br/nfe"),
    # igual aos exemplos do MOC — evita prefixo ns0 que algumas SEFAZ rejeitam.
    NSMAP = {None: NS_NFE}

    def el(tag: str, **attrs) -> etree._Element:
        return etree.Element(f"{{{NS_NFE}}}{tag}", nsmap=NSMAP, **attrs)

    def sub(parent: etree._Element, tag: str, text: str | None = None, **attrs) -> etree._Element:
        e = etree.SubElement(parent, f"{{{NS_NFE}}}{tag}", **attrs)
        if text is not None:
            e.text = text
        return e

    env = el("envEvento", versao="1.00")
    sub(env, "idLote", str(id_lote))
    evento = sub(env, "evento", None, versao="1.00")
    inf = sub(evento, "infEvento", None, Id=evento_id)
    sub(inf, "cOrgao", c_orgao)
    sub(inf, "tpAmb", tp_amb)
    sub(inf, "CNPJ", cnpj)
    sub(inf, "chNFe", chave)
    sub(inf, "dhEvento", dh)
    sub(inf, "tpEvento", "110111")
    sub(inf, "nSeqEvento", str(n_seq))
    sub(inf, "verEvento", "1.00")
    det = sub(inf, "detEvento", None, versao="1.00")
    sub(det, "descEvento", "Cancelamento")
    sub(det, "nProt", protocolo)
    sub(det, "xJust", justificativa.strip())
    return env


DS_NS = "http://www.w3.org/2000/09/xmldsig#"
C14N_ALG_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
SIG_ALG_URI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
DIGEST_ALG_URI = "http://www.w3.org/2000/09/xmldsig#sha1"
ENVELOPED_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def _c14n(node: etree._Element) -> bytes:
    """Canonicalização C14N 1.0 inclusiva (a mesma declarada no SignedInfo).

    Normaliza via serialize+reparse para que o nó vire RAIZ de documento:
    a C14N aplicada direto em subárvore com namespace default herdado gera
    declarações espúrias `xmlns=""` (quirk do libxml2), o que invalidaria o
    digest/RSA na SEFAZ. Como raiz, a saída é idêntica à que a SEFAZ calcula
    sobre o evento extraído do SOAP.
    """
    reparsed = etree.fromstring(etree.tostring(node))
    return etree.tostring(reparsed, method="c14n", exclusive=False, with_comments=False)


def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")


def assinar_inf_evento(env_evento: etree._Element, key, cert, chain) -> etree._Element:
    """Assina o infEvento (XMLDSig enveloped, RSA-SHA1) sem usar prefixos,
    no padrão exigido pelo MOC/SEFAZ (cStat 404 se houver prefixo).

    A assinatura é calculada sobre a árvore final já anexada, para que a
    canonicalização inclusiva bata com a validação da SEFAZ.
    """
    import hashlib

    inf = env_evento.find(f".//{{{NS_NFE}}}infEvento")
    if inf is None:
        raise RuntimeError("infEvento não encontrado para assinatura.")
    evento_id = inf.get("Id")
    if not evento_id:
        raise RuntimeError("infEvento sem atributo Id.")

    # 1. Digest do infEvento ainda SEM a Signature (transform enveloped a remove).
    digest_value = _b64(hashlib.sha1(_c14n(inf)).digest())

    # 2. Monta a Signature sem prefixos (xmlns default do xmldsig na própria tag).
    SIG = f"{{{DS_NS}}}"
    sig = etree.Element(SIG + "Signature", nsmap={None: DS_NS})
    si = etree.SubElement(sig, SIG + "SignedInfo")
    etree.SubElement(si, SIG + "CanonicalizationMethod", Algorithm=C14N_ALG_URI)
    etree.SubElement(si, SIG + "SignatureMethod", Algorithm=SIG_ALG_URI)
    ref = etree.SubElement(si, SIG + "Reference", URI="#" + evento_id)
    trs = etree.SubElement(ref, SIG + "Transforms")
    etree.SubElement(trs, SIG + "Transform", Algorithm=ENVELOPED_URI)
    etree.SubElement(trs, SIG + "Transform", Algorithm=C14N_ALG_URI)
    etree.SubElement(ref, SIG + "DigestMethod", Algorithm=DIGEST_ALG_URI)
    etree.SubElement(ref, SIG + "DigestValue").text = digest_value
    sig_value_el = etree.SubElement(sig, SIG + "SignatureValue")
    ki = etree.SubElement(sig, SIG + "KeyInfo")
    xd = etree.SubElement(ki, SIG + "X509Data")
    der = cert.public_bytes(serialization.Encoding.DER)
    etree.SubElement(xd, SIG + "X509Certificate").text = _b64(der)

    # 3. Anexa a Signature como IRMÃ do infEvento (filha de <evento>),
    #    que é a posição exigida pelo XSD (TEvento: infEvento + ds:Signature).
    #    O digest não muda: ele cobre só o infEvento (Reference URI).
    #    Assina o SignedInfo canonicalizado no contexto final (igual ao da SEFAZ).
    evento = env_evento.find(f".//{{{NS_NFE}}}evento")
    if evento is None:
        raise RuntimeError("elemento evento não encontrado.")
    evento.append(sig)
    signed_info_c14n = _c14n(si)
    raw_sig = key.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA1())
    sig_value_el.text = _b64(raw_sig)
    return env_evento


def envelopar_soap(env_evento_assinado: etree._Element) -> bytes:
    envelope = etree.Element(
        "{http://www.w3.org/2003/05/soap-envelope}Envelope",
        nsmap={
            "soap12": "http://www.w3.org/2003/05/soap-envelope",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsd": "http://www.w3.org/2001/XMLSchema",
        },
    )
    etree.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Header")
    body = etree.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Body")
    # nfeDadosMsg com namespace default (sem prefixo): a SEFAZ rejeita
    # "ns0:nfeDadosMsg" com 404 (Uso de prefixo de namespace nao permitido).
    dados_msg = etree.SubElement(body, f"{{{NS_WS}}}nfeDadosMsg",
                                 nsmap={None: NS_WS})
    dados_msg.append(env_evento_assinado)
    return etree.tostring(envelope, xml_declaration=True, encoding="utf-8")


def interpretar_retorno(xml_bytes: bytes) -> dict:
    root = etree.fromstring(xml_bytes)
    ns = {"nfe": NS_NFE}
    def txt(path):
        el = root.find(path, ns)
        return el.text.strip() if el is not None and el.text else ""
    return {
        "cStat": txt(".//nfe:retEvento/nfe:infEvento/nfe:cStat") or txt(".//nfe:cStat"),
        "xMotivo": txt(".//nfe:retEvento/nfe:infEvento/nfe:xMotivo") or txt(".//nfe:xMotivo"),
        "chNFe": txt(".//nfe:retEvento/nfe:infEvento/nfe:chNFe"),
        "tpEvento": txt(".//nfe:retEvento/nfe:infEvento/nfe:tpEvento"),
        "nProt": txt(".//nfe:retEvento/nfe:infEvento/nfe:nProt"),
        "dhRegEvento": txt(".//nfe:retEvento/nfe:infEvento/nfe:dhRegEvento"),
    }


def resolver_url(uf: str | None, chave: str, ambiente: str, url_override: str | None) -> tuple[str, str, str]:
    if url_override:
        return url_override, uf or "?", "override"
    cod_ibge = chave[:2]
    uf_chave = COD_IBGE_UF.get(cod_ibge, "")
    uf_final = (uf or uf_chave or "").upper()
    if not uf_final:
        raise ValueError("Não foi possível identificar a UF. Informe --uf (ex.: SP).")
    autorizador = UF_AUTORIZADOR.get(uf_final)
    if not autorizador:
        raise ValueError(f"UF '{uf_final}' desconhecida. Informe --url manualmente.")
    tabela = URLS_PROD if ambiente == "prod" else URLS_HOMOLOG
    return tabela[autorizador], uf_final, autorizador


def main() -> int:
    ap = argparse.ArgumentParser(description="Cancela uma NF-e (evento 110111) na SEFAZ.")
    ap.add_argument("--certificado", required=True, help="Caminho do certificado A1 (.pfx/.p12)")
    ap.add_argument("--senha", required=True, help="Senha do certificado .pfx")
    ap.add_argument("--xml", help="XML da NFe autorizada (nfeProc) para extrair chave/CNPJ/protocolo")
    ap.add_argument("--chave", help="Chave de acesso com 44 dígitos")
    ap.add_argument("--cnpj", help="CNPJ do emitente (só números)")
    ap.add_argument("--protocolo", help="Protocolo de autorização (nProt)")
    ap.add_argument("--justificativa", required=True, help="Motivo (15 a 255 caracteres)")
    ap.add_argument("--ambiente", choices=["prod", "producao", "homolog", "homologacao"],
                    default="prod", help="Ambiente (padrão: prod)")
    ap.add_argument("--uf", help="UF do emitente (ex.: SP). Se omitida, deriva da chave.")
    ap.add_argument("--url", help="URL do RecepcaoEvento4 (sobrescreve a tabela por UF)")
    ap.add_argument("--sequencia", type=int, default=1, help="nSeqEvento (padrão: 1)")
    ap.add_argument("--salvar-em", default=".", help="Pasta para salvar XMLs de envio/retorno")
    args = ap.parse_args()

    ambiente = "prod" if args.ambiente in ("prod", "producao") else "homolog"

    chave = somente_digitos(args.chave)
    cnpj = somente_digitos(args.cnpj)
    protocolo = (args.protocolo or "").strip()

    if args.xml:
        auto = extrair_dados_do_xml(Path(args.xml))
        chave = chave or auto.get("chave", "")
        cnpj = cnpj or somente_digitos(auto.get("cnpj"))
        protocolo = protocolo or auto.get("protocolo", "")
        print(f"[info] dados extraídos do XML: chave={chave[:10]}... "
              f"cnpj={cnpj} protocolo={protocolo}")

    try:
        validar_entradas(chave, cnpj, protocolo, args.justificativa)
    except ValueError as e:
        print(f"[erro] {e}", file=sys.stderr)
        return 2

    c_orgao = chave[:2]
    tp_amb = "1" if ambiente == "prod" else "2"

    try:
        url, uf_final, autorizador = resolver_url(args.uf, chave, ambiente, args.url)
    except ValueError as e:
        print(f"[erro] {e}", file=sys.stderr)
        return 2

    print(f"[info] UF={uf_final} autorizador={autorizador} ambiente={ambiente}")
    print(f"[info] URL={url}")

    pfx_path = Path(args.certificado)
    if not pfx_path.is_file():
        print(f"[erro] certificado não encontrado: {pfx_path}", file=sys.stderr)
        return 2

    try:
        key, cert, chain = carregar_pfx(pfx_path, args.senha)
    except Exception as e:
        print(f"[erro] falha ao ler .pfx: {e}", file=sys.stderr)
        return 2

    env = montar_env_evento(chave, cnpj, c_orgao, tp_amb, protocolo,
                            args.justificativa, n_seq=args.sequencia)
    try:
        env_signed = assinar_inf_evento(env, key, cert, chain)
    except Exception as e:
        print(f"[erro] falha ao assinar XML: {e}", file=sys.stderr)
        return 3

    out_dir = Path(args.salvar_em)
    out_dir.mkdir(parents=True, exist_ok=True)
    envio_path = out_dir / f"envEvento-cancel-{chave}.xml"
    envio_path.write_bytes(etree.tostring(env_signed, xml_declaration=True, encoding="utf-8"))
    print(f"[info] XML assinado salvo em: {envio_path}")

    soap = envelopar_soap(env_signed)

    # requests precisa de cert+key em PEM para mTLS
    tmp_cert = tempfile.NamedTemporaryFile(delete=False, suffix="-cert.pem")
    tmp_key = tempfile.NamedTemporaryFile(delete=False, suffix="-key.pem")
    try:
        for c in [cert, *chain]:
            tmp_cert.write(c.public_bytes(serialization.Encoding.PEM))
        tmp_cert.close()
        tmp_key.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        tmp_key.close()

        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{SOAP_ACTION}"',
        }
        print("[info] enviando evento de cancelamento para a SEFAZ...")
        resp = requests.post(url, data=soap, headers=headers,
                             cert=(tmp_cert.name, tmp_key.name), verify=ca_bundle(),
                             timeout=30)
    except Exception as e:
        print(f"[erro] falha de comunicação com a SEFAZ: {e}", file=sys.stderr)
        return 4
    finally:
        Path(tmp_cert.name).unlink(missing_ok=True)
        Path(tmp_key.name).unlink(missing_ok=True)

    ret_path = out_dir / f"retEvento-cancel-{chave}.xml"
    ret_path.write_bytes(resp.content)
    print(f"[info] HTTP {resp.status_code} — resposta salva em: {ret_path}")

    if resp.status_code != 200:
        print(f"[erro] SEFAZ retornou HTTP {resp.status_code}. Verifique o XML de retorno.",
              file=sys.stderr)
        return 5

    try:
        ret = interpretar_retorno(resp.content)
    except Exception as e:
        print(f"[erro] não foi possível interpretar o retorno: {e}", file=sys.stderr)
        return 5

    print(f"[retorno] cStat={ret['cStat']} xMotivo={ret['xMotivo']}")
    if ret.get("dhRegEvento"):
        print(f"[retorno] dhRegEvento={ret['dhRegEvento']} nProt={ret['nProt']}")

    if ret["cStat"] in CSTAT_SUCESSO:
        print("✅ Cancelamento homologado pela SEFAZ.")
        return 0

    print(f"❌ Cancelamento NÃO homologado. cStat={ret['cStat']} — {ret['xMotivo']}",
          file=sys.stderr)
    print("Dicas: 590/591/592 = prazo ou vínculo (mercadoria circulou, MDF-e/CT-e ativo, "
          "manifestação do destinatário). 580+ = assinatura/certificado. "
          "573 = evento duplicado (a nota pode já estar cancelada).",
          file=sys.stderr)
    return 6


if __name__ == "__main__":
    raise SystemExit(main())
