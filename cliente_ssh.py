"""Acesso aos clientes: leitura da base compartilhada e criptografia das senhas.

Modulo reusavel. Nao abre tunel nem conexao - so responde "quais sao os dados de
acesso do cliente X". Quem abre tunel e o tunel.py; quem consulta e o backend
Java ou a skill sysmo-devops.

A base e SQLite de proposito: Python le com a stdlib e Java le com sqlite-jdbc, o
que permite os dois lados usarem o mesmo arquivo. H2 seria so JVM.

As senhas ficam cifradas em AES-256-GCM, formato enc:v1:<base64(iv|cifrado)>. A
chave esta no .env da pasta da base - mesma pasta, decisao consciente para a base
poder ser movida entre projetos sem reconfigurar chave em cada um.
"""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

PREFIXO = "enc:v1:"
TAM_IV = 12
VARIAVEL_CHAVE = "CRIPTO_CHAVE"

# Raiz configuravel para o modulo servir a projetos em outros caminhos.
PASTA_BASE = Path(os.environ.get(
    "CLAUDE_DB_DIR", str(Path(__file__).resolve().parent.parent / "db")))
ARQUIVO_BASE = PASTA_BASE / "cliente_ssh.db"
ARQUIVO_ENV = PASTA_BASE / ".env"
KNOWN_HOSTS = PASTA_BASE / "known_hosts"

COLUNAS = (
    "id, nome, ssh_endereco, ssh_porta, ssh_usuario, ssh_senha, ssh_hostkey, "
    "db_endereco, db_porta, db_nome, db_usuario, db_senha, ativo, observacao"
)

DDL = """
create table if not exists cliente (
  id            integer primary key autoincrement,
  nome          text not null unique,
  ssh_endereco  text,
  ssh_porta     integer,
  ssh_usuario   text,
  ssh_senha     text,
  ssh_hostkey   text,
  db_endereco   text not null,
  db_porta      integer,
  db_nome       text,
  db_usuario    text,
  db_senha      text,
  ativo         integer not null default 1,
  observacao    text,
  dt_cadastro   text not null default (datetime('now','localtime'))
)
"""


class SemChave(RuntimeError):
    """A chave de criptografia nao esta disponivel."""


def _chave() -> bytes:
    if not ARQUIVO_ENV.exists():
        raise SemChave(
            f"{ARQUIVO_ENV} nao existe. A chave e criada na primeira execucao do "
            "backend, ou pode ser copiada de outra instalacao.")
    for linha in ARQUIVO_ENV.read_text(encoding="utf-8", errors="replace").splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha.startswith(VARIAVEL_CHAVE + "="):
            continue
        valor = linha.split("=", 1)[1].strip().strip('"').strip("'")
        bruto = base64.b64decode(valor)
        if len(bruto) != 32:
            raise SemChave(
                f"{VARIAVEL_CHAVE} deve ter 32 bytes em base64 (AES-256); "
                f"tem {len(bruto)}.")
        return bruto
    raise SemChave(f"{VARIAVEL_CHAVE} nao encontrada em {ARQUIVO_ENV}.")


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:  # pragma: no cover
        raise SemChave(
            "Modulo 'cryptography' ausente. Instale com: pip install cryptography"
        ) from e
    return AESGCM(_chave())


def cifrar(texto: str | None) -> str | None:
    """Cifra. Nulo e vazio passam sem alteracao - nao ha o que proteger."""
    if not texto:
        return texto
    if texto.startswith(PREFIXO):
        return texto
    iv = os.urandom(TAM_IV)
    cifrado = _aesgcm().encrypt(iv, texto.encode("utf-8"), None)
    return PREFIXO + base64.b64encode(iv + cifrado).decode("ascii")


def decifrar(guardado: str | None) -> str | None:
    """Decifra. Valor sem o prefixo e tratado como texto puro.

    GCM autentica: valor adulterado levanta excecao em vez de devolver lixo.
    """
    if not guardado or not guardado.startswith(PREFIXO):
        return guardado
    bruto = base64.b64decode(guardado[len(PREFIXO):])
    return _aesgcm().decrypt(bruto[:TAM_IV], bruto[TAM_IV:], None).decode("utf-8")


def conexao() -> sqlite3.Connection:
    PASTA_BASE.mkdir(parents=True, exist_ok=True)
    # timeout: o backend Java escreve na mesma base. Sem espera, uma escrita
    # concorrente devolveria "database is locked" de imediato.
    con = sqlite3.connect(ARQUIVO_BASE, timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute(DDL)
    return con


def _dto(linha: sqlite3.Row, revelar: bool) -> dict:
    d = dict(linha)
    d["ativo"] = bool(d["ativo"])
    for campo in ("ssh_senha", "db_senha"):
        d[campo] = decifrar(d[campo]) if revelar else ("***" if d[campo] else None)
    return d


def listar(somente_ativos: bool = False, revelar: bool = False) -> list[dict]:
    with conexao() as con:
        sql = f"select {COLUNAS} from cliente"
        if somente_ativos:
            sql += " where ativo = 1"
        return [_dto(l, revelar) for l in con.execute(sql + " order by nome")]


def por_nome(nome: str, revelar: bool = True) -> dict | None:
    with conexao() as con:
        l = con.execute(
            f"select {COLUNAS} from cliente where lower(nome) = lower(?)",
            (nome.strip(),)).fetchone()
        return _dto(l, revelar) if l else None


def por_id(id_cliente: int, revelar: bool = True) -> dict | None:
    with conexao() as con:
        l = con.execute(f"select {COLUNAS} from cliente where id = ?",
                        (id_cliente,)).fetchone()
        return _dto(l, revelar) if l else None


def resolver(identificador: str, revelar: bool = True) -> dict | None:
    """Aceita id (numerico) ou nome. Nao colidem: um e numerico, o outro nao."""
    texto = str(identificador).strip()
    return (por_id(int(texto), revelar) if texto.isdigit()
            else por_nome(texto, revelar))


def gravar(dados: dict) -> int:
    """Insere ou atualiza pelo nome. Devolve o id.

    Senha em branco na atualizacao preserva a atual: quem edita costuma nao ter a
    senha em maos, e sobrescrever com vazio quebraria o acesso silenciosamente.
    """
    nome = (dados.get("nome") or "").strip()
    if not nome:
        raise ValueError("Informe o nome do cliente.")
    if not (dados.get("db_endereco") or "").strip():
        raise ValueError("Informe o endereco do banco (IP interno, destino do tunel).")

    campos = ("ssh_endereco", "ssh_porta", "ssh_usuario", "ssh_hostkey",
              "db_endereco", "db_porta", "db_nome", "db_usuario",
              "ativo", "observacao")

    with conexao() as con:
        atual = con.execute("select id from cliente where lower(nome) = lower(?)",
                            (nome,)).fetchone()
        valores = {c: dados.get(c) for c in campos}
        valores["ativo"] = 1 if dados.get("ativo", True) else 0

        if atual:
            sets = ", ".join(f"{c} = :{c}" for c in campos)
            params = dict(valores, id=atual["id"])
            for campo in ("ssh_senha", "db_senha"):
                if dados.get(campo):
                    sets += f", {campo} = :{campo}"
                    params[campo] = cifrar(dados[campo])
            con.execute(f"update cliente set {sets} where id = :id", params)
            return atual["id"]

        valores["nome"] = nome
        valores["ssh_senha"] = cifrar(dados.get("ssh_senha"))
        valores["db_senha"] = cifrar(dados.get("db_senha"))
        colunas = list(valores)
        cur = con.execute(
            f"insert into cliente ({', '.join(colunas)}) "
            f"values ({', '.join(':' + c for c in colunas)})", valores)
        return cur.lastrowid


def excluir(identificador: str) -> bool:
    c = resolver(identificador, revelar=False)
    if not c:
        return False
    with conexao() as con:
        con.execute("delete from cliente where id = ?", (c["id"],))
    return True
