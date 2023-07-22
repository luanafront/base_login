import uuid
from dataclasses import dataclass
from typing import Optional, Annotated

from fastapi import FastAPI, Response, status, Header
from pydantic import BaseModel


class CadastroUsuario(BaseModel):
    nome: str
    sobrenome: str
    email: str
    senha: str


@dataclass
class UsuarioToken:
    usuario_email: str
    token: str


class LoginUsuario(BaseModel):
    email: str
    senha: str


app = FastAPI()

BANCO = []
BANCO_TOKEN = []
SALT = "Cacau"


def existe_no_banco(email: str, senha: Optional[str] = None):
    banco_esta_vazio = len(BANCO) == 0
    if banco_esta_vazio:
        return False

    for usuario_salvo in BANCO:
        existe_pelo_email = usuario_salvo.email == email
        existe_pela_senha = usuario_salvo.senha == SALT + senha if senha else None

        if senha is None:
            if existe_pelo_email:
                return True
        else:
            if existe_pelo_email and existe_pela_senha:
                return True

    return False


def pegar_token(email: str):
    for token_salvo in BANCO_TOKEN:
        if token_salvo.usuario_email == email:
            return token_salvo


@app.post("/cadastro")
def cadastrar(usuario: CadastroUsuario, response: Response):
    response.status_code = status.HTTP_201_CREATED
    ja_esta_cadastrado = existe_no_banco(usuario.email)
    if ja_esta_cadastrado:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "mensagem": "Usuario já está cadastrado"
        }
    usuario.senha = SALT + usuario.senha
    BANCO.append(usuario)
    return {
        "email": usuario.email,
        "nome": usuario.nome,
        "sobrenome": usuario.sobrenome
    }


@app.post("/login")
def login(usuario: LoginUsuario, response: Response):
    response.status_code = status.HTTP_200_OK
    if not existe_no_banco(usuario.email, usuario.senha):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {
            "mensagem": "Falha no login"
        }
    token = pegar_token(usuario.email)

    if token is None:
        token = UsuarioToken(usuario_email=usuario.email, token=str(uuid.uuid4()))
        BANCO_TOKEN.append(token)

    return {
        "mensagem": "Login feito com sucesso",
        "token": token.token
    }


@app.get("/login/verificar")
def verificar(response: Response, authorization: Annotated[str or None, Header()] = None):
    if authorization is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {
            "mensagem": "Token inválido"
        }

    token = None

    for token_salvo in BANCO_TOKEN:
        if token_salvo.token == authorization:
            token = token_salvo
            break

    if token is None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {
            "mensagem": "Token inválido"
        }

    usuario = None

    for usuario_salvo in BANCO:
        if usuario_salvo.email == token.usuario_email:
            usuario = usuario_salvo
            break

    return {
        "token": token.token,
        "usuario": {
            "nome": usuario.nome,
            "sobrenome": usuario.sobrenome,
            "email": usuario.email
        }
    }
