"""Natal em Família — amigo oculto e ceia.

FastAPI + SQLite, sem dependências além do FastAPI.

- O responsável cria uma conta (e-mail + senha), dá nome à família e define
  um código secreto. O app gera um link com UUID: /f/<uuid>.
- A família abre o link, informa o código e preenche: 3 opções de presente,
  o prato que vai levar e se é doce ou salgado.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).parent

# No Railway, monte um Volume: o caminho dele chega em RAILWAY_VOLUME_MOUNT_PATH.
# Sem volume, o banco fica no disco do container e some a cada deploy.
_volume = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
DB_PATH = Path(
    os.getenv("DB_PATH") or (Path(_volume) / "natal.db" if _volume else BASE_DIR / "natal.db")
)

DIAS_SESSAO_ADMIN = 30
DIAS_SESSAO_FAMILIA = 90
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# ---------------------------------------------------------------- banco

def conectar() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def criar_banco() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(conectar()) as con, con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                criado_em  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS familias (
                id          TEXT PRIMARY KEY,
                usuario_id  INTEGER NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
                nome        TEXT NOT NULL,
                codigo_hash TEXT NOT NULL,
                criado_em   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessoes (
                token_hash TEXT PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                familia_id TEXT REFERENCES familias(id) ON DELETE CASCADE,
                expira_em  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS participantes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                familia_id    TEXT NOT NULL REFERENCES familias(id) ON DELETE CASCADE,
                nome          TEXT NOT NULL,
                nome_chave    TEXT NOT NULL,
                presente1     TEXT NOT NULL DEFAULT '',
                presente2     TEXT NOT NULL DEFAULT '',
                presente3     TEXT NOT NULL DEFAULT '',
                comida        TEXT NOT NULL DEFAULT '',
                tipo          TEXT NOT NULL DEFAULT '',
                atualizado_em TEXT NOT NULL,
                UNIQUE (familia_id, nome_chave)
            );
            """
        )
        con.execute("DELETE FROM sessoes WHERE expira_em < ?", (int(time.time()),))


def agora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------ segurança

def gerar_hash(segredo: str) -> str:
    sal = secrets.token_bytes(16)
    h = hashlib.scrypt(segredo.encode(), salt=sal, n=2**14, r=8, p=1, dklen=32)
    return f"{sal.hex()}${h.hex()}"


def conferir_hash(segredo: str, guardado: str) -> bool:
    try:
        sal, esperado = guardado.split("$")
        h = hashlib.scrypt(segredo.encode(), salt=bytes.fromhex(sal), n=2**14, r=8, p=1, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(h.hex(), esperado)


def normalizar_codigo(codigo: str) -> str:
    """O código da família não diferencia maiúsculas nem espaços nas pontas."""
    return " ".join(codigo.split()).casefold()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def abrir_sessao(con, response: Response, request: Request, cookie: str, dias: int,
                 usuario_id: int | None = None, familia_id: str | None = None) -> None:
    token = secrets.token_urlsafe(32)
    con.execute(
        "INSERT INTO sessoes (token_hash, usuario_id, familia_id, expira_em) VALUES (?, ?, ?, ?)",
        (hash_token(token), usuario_id, familia_id, int(time.time()) + dias * 86400),
    )
    https = request.headers.get("x-forwarded-proto", request.url.scheme).startswith("https")
    response.set_cookie(cookie, token, max_age=dias * 86400, httponly=True,
                        samesite="lax", secure=https, path="/")


def ler_sessao(con, request: Request, cookie: str) -> sqlite3.Row | None:
    token = request.cookies.get(cookie)
    if not token:
        return None
    return con.execute(
        "SELECT * FROM sessoes WHERE token_hash = ? AND expira_em > ?",
        (hash_token(token), int(time.time())),
    ).fetchone()


def usuario_logado(con, request: Request) -> sqlite3.Row | None:
    s = ler_sessao(con, request, "sessao")
    if not s or not s["usuario_id"]:
        return None
    return con.execute("SELECT * FROM usuarios WHERE id = ?", (s["usuario_id"],)).fetchone()


def exigir_usuario(con, request: Request) -> sqlite3.Row:
    u = usuario_logado(con, request)
    if not u:
        raise HTTPException(401, detail={"mensagem": "Entre na sua conta."})
    return u


def cookie_familia(fid: str) -> str:
    return "fam_" + fid.replace("-", "")


def tem_acesso(con, request: Request, fid: str, dono_id: int) -> bool:
    u = usuario_logado(con, request)
    if u and u["id"] == dono_id:
        return True
    s = ler_sessao(con, request, cookie_familia(fid))
    return bool(s and s["familia_id"] == fid)


def buscar_familia(con, fid: str) -> sqlite3.Row:
    f = con.execute("SELECT * FROM familias WHERE id = ?", (fid,)).fetchone() if UUID_RE.match(fid) else None
    if not f:
        raise HTTPException(404, detail={"mensagem": "Este link de família não existe."})
    return f


# Freio simples contra tentativa e erro de senha/código (em memória, por IP).
_tentativas: dict[str, deque] = defaultdict(deque)
_trava = threading.Lock()


def frear(request: Request, alvo: str, limite: int = 10, janela: int = 900) -> None:
    ip = request.client.host if request.client else "?"
    chave = f"{ip}|{alvo}"
    t = time.time()
    with _trava:
        fila = _tentativas[chave]
        while fila and fila[0] < t - janela:
            fila.popleft()
        if len(fila) >= limite:
            raise HTTPException(
                429, detail={"mensagem": "Muitas tentativas. Espere 15 minutos e tente de novo."}
            )
        fila.append(t)


def liberar(request: Request, alvo: str) -> None:
    ip = request.client.host if request.client else "?"
    with _trava:
        _tentativas.pop(f"{ip}|{alvo}", None)


# -------------------------------------------------------------- modelos

class Credenciais(BaseModel):
    email: str = Field(max_length=254)
    senha: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def email_valido(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("E-mail inválido.")
        return v


class NovaFamilia(BaseModel):
    nome: str = Field(min_length=1, max_length=60)
    codigo: str = Field(min_length=1, max_length=60)


class AjusteFamilia(BaseModel):
    nome: str | None = Field(default=None, max_length=60)
    codigo: str | None = Field(default=None, max_length=60)


class Codigo(BaseModel):
    codigo: str = Field(max_length=60)


class Resposta(BaseModel):
    nome: str = Field(min_length=1, max_length=60)
    presentes: list[str] = Field(default_factory=list, max_length=3)
    comida: str = Field(default="", max_length=120)
    tipo: Literal["", "doce", "salgada"] = ""

    @field_validator("nome", "comida")
    @classmethod
    def limpar(cls, v: str) -> str:
        return " ".join(v.split())

    @field_validator("nome")
    @classmethod
    def nome_obrigatorio(cls, v: str) -> str:
        if not v:
            raise ValueError("Informe o nome.")
        return v

    @field_validator("presentes")
    @classmethod
    def limpar_presentes(cls, v: list[str]) -> list[str]:
        itens = [" ".join(p.split())[:120] for p in v]
        return (itens + ["", "", ""])[:3]


def validar_nome_familia(nome: str) -> str:
    nome = " ".join(nome.split())
    if not nome:
        raise HTTPException(422, detail={"mensagem": "Dê um nome para a família."})
    return nome


def validar_codigo(codigo: str) -> str:
    codigo = normalizar_codigo(codigo)
    if len(codigo) < 6:
        raise HTTPException(422, detail={"mensagem": "O código precisa ter pelo menos 6 caracteres."})
    return codigo


def familia_publica(f: sqlite3.Row | None) -> dict | None:
    return {"id": f["id"], "nome": f["nome"]} if f else None


# ------------------------------------------------------------------ app

criar_banco()
app = FastAPI(title="Natal em Família", docs_url=None, redoc_url=None, openapi_url=None)


# ---- conta do responsável

@app.post("/api/conta", status_code=201)
def criar_conta(dados: Credenciais, request: Request, response: Response) -> dict:
    frear(request, "conta", limite=5, janela=3600)
    if len(dados.senha) < 8:
        raise HTTPException(422, detail={"mensagem": "A senha precisa ter pelo menos 8 caracteres."})
    with closing(conectar()) as con, con:
        if con.execute("SELECT 1 FROM usuarios WHERE email = ?", (dados.email,)).fetchone():
            raise HTTPException(409, detail={"mensagem": "Já existe uma conta com esse e-mail. Use a aba Entrar."})
        cur = con.execute(
            "INSERT INTO usuarios (email, senha_hash, criado_em) VALUES (?, ?, ?)",
            (dados.email, gerar_hash(dados.senha), agora()),
        )
        abrir_sessao(con, response, request, "sessao", DIAS_SESSAO_ADMIN, usuario_id=cur.lastrowid)
    return {"email": dados.email, "familia": None}


@app.post("/api/login")
def login(dados: Credenciais, request: Request, response: Response) -> dict:
    frear(request, "login:" + dados.email)
    with closing(conectar()) as con, con:
        u = con.execute("SELECT * FROM usuarios WHERE email = ?", (dados.email,)).fetchone()
        if not u or not conferir_hash(dados.senha, u["senha_hash"]):
            raise HTTPException(401, detail={"mensagem": "E-mail ou senha incorretos."})
        liberar(request, "login:" + dados.email)
        abrir_sessao(con, response, request, "sessao", DIAS_SESSAO_ADMIN, usuario_id=u["id"])
        f = con.execute("SELECT * FROM familias WHERE usuario_id = ?", (u["id"],)).fetchone()
    return {"email": u["email"], "familia": familia_publica(f)}


@app.post("/api/logout", status_code=204)
def logout(request: Request, response: Response) -> None:
    token = request.cookies.get("sessao")
    if token:
        with closing(conectar()) as con, con:
            con.execute("DELETE FROM sessoes WHERE token_hash = ?", (hash_token(token),))
    response.delete_cookie("sessao", path="/")


@app.get("/api/eu")
def eu(request: Request) -> dict:
    with closing(conectar()) as con:
        u = exigir_usuario(con, request)
        f = con.execute("SELECT * FROM familias WHERE usuario_id = ?", (u["id"],)).fetchone()
    return {"email": u["email"], "familia": familia_publica(f)}


@app.post("/api/familia", status_code=201)
def criar_familia(dados: NovaFamilia, request: Request) -> dict:
    nome, codigo = validar_nome_familia(dados.nome), validar_codigo(dados.codigo)
    with closing(conectar()) as con, con:
        u = exigir_usuario(con, request)
        if con.execute("SELECT 1 FROM familias WHERE usuario_id = ?", (u["id"],)).fetchone():
            raise HTTPException(409, detail={"mensagem": "Sua conta já tem uma família."})
        fid = str(uuid.uuid4())
        con.execute(
            "INSERT INTO familias (id, usuario_id, nome, codigo_hash, criado_em) VALUES (?, ?, ?, ?, ?)",
            (fid, u["id"], nome, gerar_hash(codigo), agora()),
        )
    return {"id": fid, "nome": nome}


@app.put("/api/familia")
def ajustar_familia(dados: AjusteFamilia, request: Request) -> dict:
    with closing(conectar()) as con, con:
        u = exigir_usuario(con, request)
        f = con.execute("SELECT * FROM familias WHERE usuario_id = ?", (u["id"],)).fetchone()
        if not f:
            raise HTTPException(404, detail={"mensagem": "Crie a família primeiro."})
        if dados.nome is not None:
            con.execute("UPDATE familias SET nome = ? WHERE id = ?", (validar_nome_familia(dados.nome), f["id"]))
        if dados.codigo is not None:
            con.execute("UPDATE familias SET codigo_hash = ? WHERE id = ?",
                        (gerar_hash(validar_codigo(dados.codigo)), f["id"]))
            # Código novo: quem entrou com o antigo precisa informar o novo.
            con.execute("DELETE FROM sessoes WHERE familia_id = ?", (f["id"],))
        f = con.execute("SELECT * FROM familias WHERE id = ?", (f["id"],)).fetchone()
    return familia_publica(f)


# ---- página da família

@app.get("/api/f/{fid}")
def ver_familia(fid: str, request: Request) -> dict:
    with closing(conectar()) as con:
        f = buscar_familia(con, fid)
        return {"nome": f["nome"], "liberado": tem_acesso(con, request, fid, f["usuario_id"])}


@app.post("/api/f/{fid}/entrar")
def entrar(fid: str, dados: Codigo, request: Request, response: Response) -> dict:
    frear(request, "codigo:" + fid)
    with closing(conectar()) as con, con:
        f = buscar_familia(con, fid)
        if not conferir_hash(normalizar_codigo(dados.codigo), f["codigo_hash"]):
            raise HTTPException(401, detail={"mensagem": "Código incorreto. Confira com quem te mandou o link."})
        liberar(request, "codigo:" + fid)
        abrir_sessao(con, response, request, cookie_familia(fid), DIAS_SESSAO_FAMILIA, familia_id=fid)
    return {"nome": f["nome"], "liberado": True}


def acesso(fid: str, request: Request) -> str:
    """Dependência: garante que quem chama já informou o código desta família."""
    with closing(conectar()) as con:
        f = buscar_familia(con, fid)
        if not tem_acesso(con, request, fid, f["usuario_id"]):
            raise HTTPException(401, detail={"mensagem": "Informe o código da família."})
    return fid


def para_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "nome": row["nome"],
        "presentes": [row["presente1"], row["presente2"], row["presente3"]],
        "comida": row["comida"],
        "tipo": row["tipo"],
        "atualizado_em": row["atualizado_em"],
    }


def valores(r: Resposta) -> tuple:
    tipo = r.tipo if r.comida else ""
    return (r.nome, r.nome.casefold(), *r.presentes, r.comida, tipo, agora())


@app.get("/api/f/{fid}/participantes")
def listar(fid: str = Depends(acesso)) -> list[dict]:
    with closing(conectar()) as con:
        rows = con.execute(
            "SELECT * FROM participantes WHERE familia_id = ? ORDER BY nome_chave", (fid,)
        ).fetchall()
    return [para_dict(r) for r in rows]


@app.post("/api/f/{fid}/participantes", status_code=201)
def criar(r: Resposta, fid: str = Depends(acesso)) -> dict:
    with closing(conectar()) as con, con:
        existente = con.execute(
            "SELECT id FROM participantes WHERE familia_id = ? AND nome_chave = ?",
            (fid, r.nome.casefold()),
        ).fetchone()
        if existente:
            raise HTTPException(
                409, detail={"mensagem": "Já existe uma resposta com esse nome.", "id": existente["id"]}
            )
        cur = con.execute(
            """INSERT INTO participantes
               (familia_id, nome, nome_chave, presente1, presente2, presente3, comida, tipo, atualizado_em)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fid, *valores(r)),
        )
        row = con.execute("SELECT * FROM participantes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return para_dict(row)


@app.put("/api/f/{fid}/participantes/{pid}")
def atualizar(pid: int, r: Resposta, fid: str = Depends(acesso)) -> dict:
    with closing(conectar()) as con, con:
        if not con.execute(
            "SELECT 1 FROM participantes WHERE id = ? AND familia_id = ?", (pid, fid)
        ).fetchone():
            raise HTTPException(404, detail={"mensagem": "Essa resposta não existe mais."})
        outro = con.execute(
            "SELECT id FROM participantes WHERE familia_id = ? AND nome_chave = ? AND id <> ?",
            (fid, r.nome.casefold(), pid),
        ).fetchone()
        if outro:
            raise HTTPException(
                409, detail={"mensagem": "Outra pessoa já usa esse nome.", "id": outro["id"]}
            )
        con.execute(
            """UPDATE participantes
               SET nome = ?, nome_chave = ?, presente1 = ?, presente2 = ?, presente3 = ?,
                   comida = ?, tipo = ?, atualizado_em = ?
               WHERE id = ? AND familia_id = ?""",
            (*valores(r), pid, fid),
        )
        row = con.execute("SELECT * FROM participantes WHERE id = ?", (pid,)).fetchone()
    return para_dict(row)


@app.delete("/api/f/{fid}/participantes/{pid}", status_code=204)
def remover(pid: int, fid: str = Depends(acesso)) -> None:
    with closing(conectar()) as con, con:
        con.execute("DELETE FROM participantes WHERE id = ? AND familia_id = ?", (pid, fid))


# ---- páginas

SEM_CACHE = {"Cache-Control": "no-cache"}


@app.get("/saude")
def saude() -> dict:
    return {"ok": True}


@app.get("/")
def pagina_conta() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "conta.html", headers=SEM_CACHE)


@app.get("/f/{fid}")
def pagina_familia(fid: str) -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "familia.html", headers=SEM_CACHE)


# ---- instalação (PWA)

def manifesto(nome: str, inicio: str) -> JSONResponse:
    def icone(arq: str, tam: int, uso: str) -> dict:
        return {"src": f"/static/icones/{arq}", "sizes": f"{tam}x{tam}", "type": "image/png", "purpose": uso}

    return JSONResponse(
        {
            "name": nome,
            "short_name": nome[:24],
            "description": "Amigo oculto e ceia de Natal da família.",
            "lang": "pt-BR",
            "id": inicio,
            "start_url": inicio,
            "scope": "/",
            "display": "standalone",
            "background_color": "#F3F6F4",
            "theme_color": "#0F3D2E",
            "icons": [
                icone("icone-192.png", 192, "any"),
                icone("icone-512.png", 512, "any"),
                icone("icone-maskable-512.png", 512, "maskable"),
            ],
        },
        media_type="application/manifest+json",
        headers=SEM_CACHE,
    )


@app.get("/manifest.webmanifest")
def manifesto_conta() -> JSONResponse:
    return manifesto("Natal em Família", "/")


@app.get("/f/{fid}/manifest.webmanifest")
def manifesto_familia(fid: str) -> JSONResponse:
    """Cada família instala o app abrindo direto na própria página."""
    with closing(conectar()) as con:
        f = buscar_familia(con, fid)
    return manifesto(f["nome"], f"/f/{fid}")


@app.get("/sw.js")
def service_worker() -> FileResponse:
    # Servido na raiz para o service worker valer para o site todo.
    return FileResponse(BASE_DIR / "static" / "sw.js", media_type="text/javascript", headers=SEM_CACHE)


app.mount("/font", StaticFiles(directory=BASE_DIR / "font"), name="font")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
