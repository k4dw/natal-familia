# Natal em Família

Amigo oculto e ceia de Natal da família em um link só.

**Quem organiza** cria uma conta (e-mail + senha), dá nome à família e define
um código secreto. O app gera um link com UUID (`/f/<uuid>`).

**A família** abre o link, digita o código uma vez por aparelho e informa:

1. **Amigo oculto** — 3 opções de presente
2. **Ceia** — o prato que vai levar
3. **Doce ou salgado** — o tipo do prato

Stack: FastAPI + SQLite (biblioteca padrão) + HTML/CSS/JS sem build.

## Rodar local

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Abra http://localhost:8000.

## Publicar no Railway

1. **New Project → Deploy from GitHub repo**. O `Dockerfile` é detectado sozinho.
2. **Crie um Volume** no serviço e monte em `/data`. Sem isso o SQLite é
   apagado a cada deploy. O app lê `RAILWAY_VOLUME_MOUNT_PATH` e grava
   `natal.db` lá dentro.
3. Em **Settings → Networking**, gere um domínio público.
4. Abra o domínio, crie a conta, a família e copie o link.

Variável opcional: `DB_PATH` (caminho completo do arquivo do banco).

## Páginas

| Rota | O que é |
| --- | --- |
| `/` | Conta de quem organiza: criar conta, entrar, painel com o link |
| `/f/<uuid>` | Página da família (pede o código no primeiro acesso) |

## API

| Método | Rota | Acesso |
| --- | --- | --- |
| POST | `/api/conta`, `/api/login`, `/api/logout` | público |
| GET | `/api/eu` | conta |
| POST / PUT | `/api/familia` | conta (cria / troca nome ou código) |
| GET | `/api/f/{uuid}` | público (nome da família e se já está liberado) |
| POST | `/api/f/{uuid}/entrar` | público (confere o código) |
| GET / POST | `/api/f/{uuid}/participantes` | código da família |
| PUT / DELETE | `/api/f/{uuid}/participantes/{id}` | código da família |

## Segurança

- Senha e código guardados com scrypt; sessões são tokens aleatórios em cookie
  `HttpOnly`, com apenas o SHA-256 no banco.
- O código não diferencia maiúsculas. Trocar o código derruba os acessos antigos.
- Limite de 10 tentativas de senha/código por IP a cada 15 minutos (em memória).
- Uma família por conta. Não há verificação de e-mail nem "esqueci minha
  senha": o app não envia e-mails.
- Dentro da família, qualquer pessoa pode editar ou apagar qualquer resposta.
