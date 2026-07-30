"""Abre o tunel SSH ate o banco de um cliente, lendo os dados da base compartilhada.

Reusavel por qualquer projeto: recebe o cliente (id ou nome), abre o encaminhamento
e imprime em stdout uma linha JSON com a porta local. Quem chamou conecta em
127.0.0.1:<porta>.

    python tunel.py --abrir cegil
    {"cliente": "Cegil", "porta": 53197, "pid": 12345, "destino": "192.168.2.5:5432"}

    python tunel.py --fechar 12345
    python tunel.py --listar

    echo '{"ssh_endereco":"...","ssh_usuario":"...","ssh_senha":"...","db_endereco":"..."}' \\
      | python tunel.py --testar
    {"cliente": "(teste)", "porta": 53198, "pid": 12346, "destino": "...", "teste": true}

--testar serve para validar um acesso que ainda nao esta no cadastro (ou uma senha
nova): recebe os dados por stdin, nao le nem grava a base, e nao entra no registro
de tuneis. Quem chamou fecha pelo pid.

Porta local efemera por padrao (o sistema escolhe uma livre). Porta fixa dava
colisao entre clientes e com outros processos, e obrigava um cliente por vez.

A senha SSH nunca vai para stdout nem para a linha de comando: no Windows e
escrita num .bat temporario; no Linux vai por SSH_ASKPASS a partir de /dev/shm.
Isso evita que apareca em `ps` ou no historico do shell.

Host key: exigida e conferida contra o pino gravado no cadastro (ssh_hostkey).
Sem pino, a primeira conexao grava a chave apresentada e avisa - trocas
posteriores passam a ser recusadas.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cliente_ssh  # noqa: E402

IS_LINUX = sys.platform.startswith("linux")


def achar_plink() -> str:
    """Localiza o plink.exe. Nada fixo: variavel de ambiente, PATH, e por ultimo
    os diretorios usuais de instalacao - em qualquer unidade, nao so C:."""
    do_ambiente = os.environ.get("PLINK")
    if do_ambiente and Path(traduzir(do_ambiente)).exists():
        return janela(Path(traduzir(do_ambiente)))

    from shutil import which
    achado = which("plink.exe") or which("plink")
    if achado:
        # O plink e chamado pelo cmd.exe: o caminho tem que estar em formato
        # Windows, mesmo quando o which do WSL devolve /mnt/c/...
        return janela(Path(achado))

    unidades = ["c", "d", "e"] if IS_LINUX else [None]
    for unidade in unidades:
        raizes = ([Path(f"/mnt/{unidade}/Program Files"),
                   Path(f"/mnt/{unidade}/Program Files (x86)")] if IS_LINUX
                  else [Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")])
        for raiz in raizes:
            if not raiz.exists():
                continue
            for candidato in raiz.glob("PuTTY*/plink.exe"):
                return janela(candidato)
    raise RuntimeError(
        "plink.exe nao encontrado. Instale o PuTTY, coloque no PATH, ou aponte a "
        "variavel PLINK para o executavel.")


def traduzir(caminho_windows: str) -> str:
    r"""C:\x -> /mnt/c/x quando rodando no WSL, para poder testar existencia."""
    if not IS_LINUX or len(caminho_windows) < 2 or caminho_windows[1] != ":":
        return caminho_windows
    unidade = caminho_windows[0].lower()
    return f"/mnt/{unidade}/" + caminho_windows[2:].lstrip("\\/").replace("\\", "/")


def janela(caminho: Path) -> str:
    r"""/mnt/c/x -> C:\x, formato que o cmd.exe entende."""
    partes = caminho.parts
    if len(partes) > 2 and partes[1] == "mnt":
        return f"{partes[2].upper()}:\\" + "\\".join(partes[3:])
    return str(caminho)

# Rodando no WSL, o tunel precisa ser aberto por um binario WINDOWS quando quem
# consome tambem e Windows (backend Java): o WSL2 em NAT tem loopback proprio, e
# um tunel aberto pelo ssh do WSL nao e alcancado pelo lado Windows.
USAR_WINDOWS = not IS_LINUX or Path("/mnt/c/Windows/System32/cmd.exe").exists()


def porta_livre() -> int:
    """Pede ao sistema uma porta livre. Ha uma janela entre fechar e o plink
    abrir; e curta e o proprio plink falha alto se perder a corrida."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def escutando(porta: int) -> bool:
    """Alguem escuta na porta.

    Rodando no WSL com tunel do lado Windows, o teste TEM que ser feito pelo
    Windows: o WSL2 em NAT tem loopback proprio e nunca veria o listener do
    plink, fazendo a espera falhar mesmo com o tunel de pe.
    """
    if IS_LINUX and USAR_WINDOWS:
        r = subprocess.run(
            ["cmd.exe", "/c", f"netstat -ano | findstr LISTENING | findstr :{porta}"],
            capture_output=True, text=True, errors="replace", cwd="/mnt/c")
        return any(f":{porta}" in l.split()[1] for l in r.stdout.splitlines()
                   if len(l.split()) > 1)
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", porta)) == 0


def pid_do_listener(porta: int) -> int:
    """Pid WINDOWS de quem escuta na porta.

    O Popen devolve o pid do cmd.exe - e, rodando no WSL, um pid do WSL, que o
    taskkill nem reconhece. Quem precisa morrer e o plink, e so o Windows sabe o
    pid dele.
    """
    cmd = ["cmd.exe", "/c", f"netstat -ano | findstr LISTENING | findstr :{porta}"]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                       cwd="/mnt/c" if IS_LINUX else None)
    for linha in r.stdout.splitlines():
        partes = linha.split()
        if len(partes) >= 5 and partes[1].endswith(f":{porta}"):
            return int(partes[-1])
    return 0


def win_temp() -> tuple[Path, str]:
    if IS_LINUX:
        usuario = os.environ.get("USER", "s277")
        return Path(f"/mnt/c/Users/{usuario}/AppData/Local/Temp"), \
            rf"C:\Users\{usuario}\AppData\Local\Temp"
    temp = os.environ.get("TEMP", r"C:\Windows\Temp")
    return Path(temp), temp


def candidatos_keyscan() -> list[str]:
    """ssh-keyscan disponiveis, na ordem em que valem a tentativa.

    O do System32 vem DEPOIS do Git for Windows de proposito: o
    OpenSSH_for_Windows_9.5p2 anuncia o KEX sntrup761x25519-sha512@openssh.com sem
    implementar, e contra servidor que o oferece (OpenSSH 9.6 do Ubuntu, por
    exemplo) ele aborta com "choose_kex: unsupported KEX method" - devolve so o
    banner, nenhuma chave. O 9.1 do Git nem anuncia, negocia outro e funciona.

    Ordem, nao escolha unica: qualquer um pode nao estar instalado, e qual falha
    depende do servidor do outro lado.
    """
    if IS_LINUX:
        return ["ssh-keyscan"]
    fixos = [r"C:\Program Files\Git\usr\bin\ssh-keyscan.exe",
             r"C:\Windows\System32\OpenSSH\ssh-keyscan.exe"]
    return [c for c in fixos if Path(c).exists()] + ["ssh-keyscan"]


# Motivo da ultima falha de keyscan, para a mensagem de erro nao ficar so em "sem
# resposta" - foi justamente isso que fez procurar endereco e porta errados quando
# o problema era incompatibilidade de KEX.
_ULTIMA_FALHA_KEYSCAN = ""


def fingerprint_remota(cliente: dict, tipo: str) -> str:
    """Fingerprint SHA256 da host key, via ssh-keyscan. Vazio quando nenhum serve."""
    global _ULTIMA_FALHA_KEYSCAN
    falhas: list[str] = []
    for binario in candidatos_keyscan():
        cmd = [binario, "-t", tipo, "-p", str(cliente["ssh_porta"] or 22),
               cliente["ssh_endereco"]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        except OSError as e:
            falhas.append(f"{binario}: {e}")
            continue
        linhas = [l for l in r.stdout.splitlines() if l and not l.startswith("#")]
        if not linhas:
            detalhe = " | ".join(l.strip() for l in r.stderr.splitlines() if l.strip())
            falhas.append(f"{Path(binario).name}: {detalhe or 'nenhuma chave na saida'}")
            continue
        proc = subprocess.run(["ssh-keygen", "-lf", "-"], input="\n".join(linhas),
                              capture_output=True, text=True, errors="replace")
        m = re.search(r"(SHA256:[A-Za-z0-9+/=]+)", proc.stdout)
        if m:
            return m.group(1)
        falhas.append(f"{Path(binario).name}: ssh-keygen nao extraiu fingerprint")
    _ULTIMA_FALHA_KEYSCAN = "; ".join(falhas)
    return ""


def extrair_fingerprint(pino: str | None) -> str:
    """SHA256:... de dentro do pino gravado (que pode vir no formato completo do
    ssh-keygen -lf: 'ssh-ed25519 255 SHA256:... comentario')."""
    if not pino:
        return ""
    m = re.search(r"(SHA256:[A-Za-z0-9+/=]+)", pino)
    return m.group(1) if m else pino.strip()


def conferir_hostkey(cliente: dict) -> str:
    """Recusa se a host key divergir do pino gravado no cadastro.

    Sem pino, DESCOBRE a chave apresentada e a fixa no dicionario para esta conexao,
    devolvendo qual foi. Nao e frouxidao acrescentada: o plink roda com -batch e
    recusa chave desconhecida, entao sem isso cliente sem pino no cadastro nao
    conectava de jeito nenhum - e a tela promete justamente o contrario ("em branco,
    a conexao e feita sem conferir a identidade do servidor").

    Quem chama avisa a quem opera qual chave foi aceita, para poder ser conferida por
    canal independente e gravada. Gravar sozinho seria confiar sem conferencia.
    """
    pino = (cliente.get("ssh_hostkey") or "").strip()
    if not pino:
        atual = (fingerprint_remota(cliente, "ed25519")
                 or fingerprint_remota(cliente, "rsa")
                 or fingerprint_remota(cliente, "ecdsa"))
        if not atual:
            raise RuntimeError(
                f"Nao obtive a host key de {cliente['ssh_endereco']}:"
                f"{cliente['ssh_porta'] or 22}. Confira endereco e porta de SSH. "
                f"Tentativas: {_ULTIMA_FALHA_KEYSCAN}")
        print(f"[aviso] host key nao fixada para {cliente['nome']}. "
              f"Aceita agora: {atual}\n"
              f"        Confira por canal independente e grave em ssh_hostkey "
              f"para que trocas futuras sejam recusadas.", file=sys.stderr)
        # Fixa so para esta conexao: o cadastro nao e alterado daqui.
        cliente["ssh_hostkey"] = atual
        return atual

    m = re.search(r"(SHA256:[A-Za-z0-9+/=]+)", pino)
    esperado = m.group(1) if m else pino
    tipo = "ed25519"
    if "rsa" in pino.lower():
        tipo = "rsa"
    elif "ecdsa" in pino.lower():
        tipo = "ecdsa"

    atual = fingerprint_remota(cliente, tipo)
    if not atual:
        raise RuntimeError(
            f"Nao obtive a host key {tipo} de {cliente['ssh_endereco']}. "
            f"Tentativas: {_ULTIMA_FALHA_KEYSCAN}")
    if atual != esperado:
        raise RuntimeError(
            f"ALERTA: host key DIFERENTE da fixada no cadastro.\n"
            f"  fixada  : {esperado}\n"
            f"  servidor: {atual}\n"
            "Conexao abortada. Pode ser troca legitima de servidor ou "
            "interceptacao - confirme por canal independente antes de atualizar.")
    return ""


def escapar_bat(valor: object) -> str:
    """Escapa um valor interpolado no .bat.

    O cmd.exe expande `%...%` ANTES de o plink ver os argumentos, e faz isso tambem
    dentro de aspas. Um `%` no meio de um valor nao some sozinho: o cmd procura o `%`
    de fechamento no resto da linha e engole tudo que esta entre os dois - inclusive
    parametros seguintes.

    Foi essa a causa de um cliente com `%` na senha falhar sempre com "Cannot confirm a
    host key in batch mode": o `-hostkey` seguinte desaparecia da linha, e o plink caia
    no caminho de chave desconhecida. `%%` chega ao programa como um `%`.
    """
    return str(valor).replace("%", "%%")


def limpar_restos(temp_wsl: Path) -> None:
    """Apaga sobras de execucoes anteriores no Temp.

    O `.pw` sai no finally, mas processo morto a forca (kill, queda de energia) entre a
    escrita e o finally deixa uma senha em texto puro no disco. Uma hora e folga
    generosa: uma abertura de tunel dura segundos, entao nada em uso e alcancado.

    Os `.log` tambem entram: o plink os mantem abertos enquanto o tunel vive, e por isso
    quase nunca somem na hora - iam acumulando indefinidamente.
    """
    limite = time.time() - 3600
    for p in list(temp_wsl.glob("tunel-*.pw")) + list(temp_wsl.glob("tunel-*.bat")) \
            + list(temp_wsl.glob("tunel-*.bat.log")):
        try:
            if p.stat().st_mtime < limite:
                apagar(p)
        except OSError:
            pass


def abrir_windows(cliente: dict, porta: int) -> int:
    """plink.exe em background. A senha vai por arquivo, nunca em `ps` nem no .bat."""
    temp_wsl, temp_win = win_temp()
    limpar_restos(temp_wsl)
    nome = f"tunel-{cliente['id']}-{porta}.bat"
    bat_wsl = temp_wsl / nome
    destino = f"{cliente['db_endereco']}:{cliente['db_porta'] or 5432}"

    # -hostkey quando ha pino: com -batch o plink recusa chave desconhecida, e
    # sem o parametro dependeriamos do cache do PuTTY - que nao existe em maquina
    # nova nem quando outro usuario roda.
    pino = extrair_fingerprint(cliente.get("ssh_hostkey"))
    parametro_hostkey = f'-hostkey "{pino}" ' if pino else ""

    # Senha por arquivo (-pwfile), nao por -pw: assim ela nao passa pelo parser do
    # cmd.exe, que mexe em `%` e trata `&` `^` `!` como sintaxe. Senha real tem esses
    # caracteres, e com -pw a linha chegava alterada - ou quebrada - ao plink.
    # Apagado no finally, como o .bat.
    pw_nome = f"tunel-{cliente['id']}-{porta}.pw"
    pw_wsl = temp_wsl / pw_nome
    pw_win = rf"{temp_win}\{pw_nome}" if IS_LINUX else str(pw_wsl)
    pw_wsl.write_text(cliente["ssh_senha"], encoding="cp1252", newline="")

    bat_wsl.write_text(
        "@echo off\r\n"
        f'"{achar_plink()}" -ssh -N -batch '
        f'-P {int(cliente["ssh_porta"] or 22)} '
        f'-l {escapar_bat(cliente["ssh_usuario"])} '
        f'-pwfile "{escapar_bat(pw_win)}" '
        f'{parametro_hostkey}'
        f'-L 127.0.0.1:{porta}:{escapar_bat(destino)} '
        f'{escapar_bat(cliente["ssh_endereco"])}\r\n',
        encoding="cp1252", newline="",
    )

    if IS_LINUX:
        cmd = ["cmd.exe", "/c", rf"{temp_win}\{nome}"]
        cwd = "/mnt/c"
    else:
        cmd = ["cmd.exe", "/c", str(bat_wsl)]
        cwd = None

    # A saida do plink vai para arquivo, nao para DEVNULL: quando ele recusa a
    # conexao, o motivo esta ai ("Access denied", "Host does not exist", host key
    # divergente). Antes o erro era sempre "plink encerrou sem abrir o tunel" e
    # nao dava para distinguir senha errada de servidor inalcancavel.
    #
    # Arquivo e nao PIPE: o processo fica em background e ninguem le o cano depois
    # que esta funcao retorna - o buffer encheria e travaria o tunel.
    log = temp_wsl / f"{nome}.log"
    saida = log.open("wb")
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, start_new_session=True,
                                stdin=subprocess.DEVNULL,
                                stdout=saida, stderr=subprocess.STDOUT)
        for _ in range(40):
            if escutando(porta):
                # Pid do plink no Windows, nao do cmd.exe: e ele que sustenta o
                # tunel e e ele que o --fechar precisa encerrar.
                return pid_do_listener(porta) or proc.pid
            if proc.poll() is not None:
                raise RuntimeError("plink encerrou sem abrir o tunel. "
                                   + (detalhe_plink(log) or "Confira usuario, senha e "
                                      "host key do cadastro."))
            time.sleep(0.5)
        raise RuntimeError(f"tunel nao subiu em 20s na porta {porta}. "
                           + detalhe_plink(log))
    finally:
        saida.close()
        # O arquivo de senha some sempre, inclusive no caminho de erro: o plink le a
        # senha na autenticacao, que ja aconteceu quando a porta abriu ou quando o
        # processo morreu. O .bat vai junto por simetria.
        apagar(pw_wsl)
        apagar(bat_wsl)
        # O log fica aberto pelo plink enquanto o tunel vive, e o Windows recusa
        # apagar arquivo em uso - por isso apagar sem falhar. No caminho de erro o
        # plink ja morreu e a remocao funciona; no de sucesso o arquivo (sem segredo,
        # so a saida do plink) sai quando o tunel for fechado.
        apagar(log)


def apagar(caminho: Path) -> None:
    """Remove sem derrubar quem chamou. Arquivo em uso no Windows levanta OSError."""
    try:
        caminho.unlink(missing_ok=True)
    except OSError:
        pass


def detalhe_plink(log: Path) -> str:
    """O que o plink escreveu, para a mensagem de erro dizer a causa."""
    try:
        texto = log.read_text(encoding="cp1252", errors="replace").strip()
    except OSError:
        return ""
    linhas = [l.strip() for l in texto.splitlines() if l.strip()]
    return " / ".join(linhas[-3:])


def abrir_linux(cliente: dict, porta: int) -> int:
    """ssh -L em background. Senha via SSH_ASKPASS a partir de /dev/shm."""
    askpass = Path("/dev/shm/tunel-askpass.sh")
    askpass.write_text(
        "#!/bin/sh\n"
        f"printf '%s' {shlex.quote(cliente['ssh_senha'])}\n", encoding="utf-8")
    askpass.chmod(0o700)
    destino = f"{cliente['db_endereco']}:{cliente['db_porta'] or 5432}"
    try:
        ambiente = {
            **os.environ,
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": os.environ.get("DISPLAY", ":0"),
        }
        proc = subprocess.Popen(
            ["setsid", "ssh", "-N",
             "-L", f"127.0.0.1:{porta}:{destino}",
             "-p", str(cliente["ssh_porta"] or 22),
             "-o", "StrictHostKeyChecking=accept-new",
             "-o", f"UserKnownHostsFile={cliente_ssh.KNOWN_HOSTS}",
             "-o", "NumberOfPasswordPrompts=1",
             "-o", "ExitOnForwardFailure=yes",
             "-o", "ServerAliveInterval=30",
             f"{cliente['ssh_usuario']}@{cliente['ssh_endereco']}"],
            env=ambiente, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True)
        for _ in range(40):
            if escutando(porta):
                return proc.pid
            if proc.poll() is not None:
                erro = (proc.stderr.read() or b"").decode(errors="replace")
                raise RuntimeError(erro.strip() or "ssh encerrou sem abrir o tunel.")
            time.sleep(0.5)
        raise RuntimeError(f"tunel nao subiu em 20s na porta {porta}.")
    finally:
        askpass.unlink(missing_ok=True)


REGISTRO = cliente_ssh.PASTA_BASE / "tuneis.json"


def registro_ler() -> dict:
    """Tuneis abertos, por id de cliente. Existe para varios processos
    reaproveitarem o mesmo tunel em vez de cada um abrir o seu."""
    if not REGISTRO.exists():
        return {}
    try:
        return json.loads(REGISTRO.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def registro_gravar(dados: dict) -> None:
    REGISTRO.write_text(json.dumps(dados, ensure_ascii=False, indent=2),
                        encoding="utf-8")


def registro_por_cliente(id_cliente: int) -> dict | None:
    """Entrada do registro se o tunel ainda estiver de pe. Limpa se caiu."""
    reg = registro_ler()
    item = reg.get(str(id_cliente))
    if not item:
        return None
    if escutando(item.get("porta", 0)):
        return item
    reg.pop(str(id_cliente), None)
    registro_gravar(reg)
    return None


def abrir(identificador: str, porta: int | None = None) -> dict:
    cliente = cliente_ssh.resolver(identificador)
    if not cliente:
        raise RuntimeError(f"Cliente nao cadastrado: {identificador}")
    if not cliente["ativo"]:
        raise RuntimeError(f"Cliente inativo: {cliente['nome']}")
    for campo in ("ssh_endereco", "ssh_usuario", "ssh_senha", "db_endereco"):
        if not cliente.get(campo):
            raise RuntimeError(
                f"Cliente {cliente['nome']} sem {campo} no cadastro.")

    # Reusa o tunel ja aberto: cada abertura custa um handshake SSH, e nada
    # ganha em ter dois encaminhamentos para o mesmo destino.
    existente = registro_por_cliente(cliente["id"])
    if existente and not porta:
        return dict(existente, reusado=True)

    conferir_hostkey(cliente)

    porta = porta or porta_livre()
    pid = (abrir_windows if USAR_WINDOWS else abrir_linux)(cliente, porta)
    item = {
        "cliente": cliente["nome"],
        "id": cliente["id"],
        "porta": porta,
        "pid": pid,
        "destino": f"{cliente['db_endereco']}:{cliente['db_porta'] or 5432}",
        "base": cliente["db_nome"],
        "usuario": cliente["db_usuario"],
    }
    reg = registro_ler()
    reg[str(cliente["id"])] = item
    registro_gravar(reg)
    return item


def testar(dados: dict) -> dict:
    """Abre um tunel com dados informados na chamada, sem passar pelo cadastro.

    Existe para a tela de Clientes conseguir validar um acesso ANTES de gravar - ou
    uma senha nova que ainda nao esta na base. Recebe o mesmo dicionario que o
    cadastro produz, mas por stdin, para a senha nao aparecer em `ps` nem no
    historico do shell.

    Nao entra no registro de tuneis abertos: um teste nao deve ser reaproveitado
    como tunel de trabalho, e o chamador fecha pelo pid devolvido.
    """
    faltando = [c for c in ("ssh_endereco", "ssh_usuario", "ssh_senha", "db_endereco")
                if not dados.get(c)]
    if faltando:
        raise RuntimeError("Informe " + ", ".join(faltando) + ".")

    cliente = {
        "id": 0,
        "nome": dados.get("nome") or "(teste)",
        "ativo": 1,
        "ssh_endereco": dados["ssh_endereco"],
        "ssh_porta": dados.get("ssh_porta") or 22,
        "ssh_usuario": dados["ssh_usuario"],
        "ssh_senha": dados["ssh_senha"],
        "ssh_hostkey": dados.get("ssh_hostkey") or "",
        "db_endereco": dados["db_endereco"],
        "db_porta": dados.get("db_porta") or 5432,
        "db_nome": dados.get("db_nome") or "",
        "db_usuario": dados.get("db_usuario") or "",
    }

    apresentada = conferir_hostkey(cliente)

    porta = porta_livre()
    pid = (abrir_windows if USAR_WINDOWS else abrir_linux)(cliente, porta)
    return {
        "cliente": cliente["nome"],
        "porta": porta,
        "pid": pid,
        "destino": f"{cliente['db_endereco']}:{cliente['db_porta']}",
        "hostkey": apresentada,
        "teste": True,
    }


def fechar_cliente(identificador: str) -> bool:
    """Fecha o tunel de um cliente pelo registro, sem precisar saber o pid."""
    c = cliente_ssh.resolver(identificador, revelar=False)
    if not c:
        return False
    reg = registro_ler()
    item = reg.pop(str(c["id"]), None)
    registro_gravar(reg)
    return fechar(item["pid"]) if item else False


def abertos() -> list[dict]:
    """Tuneis vivos. Entradas mortas saem do registro na conferencia."""
    reg = registro_ler()
    vivos = {k: v for k, v in reg.items() if escutando(v.get("porta", 0))}
    if len(vivos) != len(reg):
        registro_gravar(vivos)
    return list(vivos.values())


def fechar(pid: int) -> bool:
    if USAR_WINDOWS:
        # errors="replace": a saida do taskkill vem em cp850 e derrubava a
        # decodificacao, escondendo o resultado real da operacao.
        r = subprocess.run(["cmd.exe", "/c", f"taskkill /PID {pid} /T /F"],
                           capture_output=True, text=True, errors="replace",
                           cwd="/mnt/c" if IS_LINUX else None)
        return r.returncode == 0
    try:
        os.kill(pid, 15)
        return True
    except ProcessLookupError:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--abrir", metavar="CLIENTE", help="id ou nome do cliente")
    g.add_argument("--fechar", metavar="PID", type=int)
    g.add_argument("--fechar-cliente", metavar="CLIENTE",
                   help="fecha pelo cadastro, sem precisar do pid")
    g.add_argument("--listar", action="store_true", help="clientes cadastrados")
    g.add_argument("--abertos", action="store_true", help="tuneis no ar")
    g.add_argument("--porta", metavar="CLIENTE", dest="porta_de",
                   help="porta local do cliente, abrindo o tunel se preciso")
    g.add_argument("--testar", action="store_true",
                   help="abre um tunel com os dados de acesso lidos de stdin (JSON), "
                        "sem consultar nem gravar no cadastro; devolve porta e pid")
    p.add_argument("--porta-fixa", type=int, dest="porta",
                   help="porta local fixa (padrao: efemera, escolhida pelo sistema)")
    a = p.parse_args()

    try:
        if a.listar:
            for c in cliente_ssh.listar(revelar=False):
                marca = "" if c["ativo"] else "  (inativo)"
                print(f"{c['id']:>3}  {c['nome']:<24} "
                      f"{c['ssh_usuario'] or '-'}@{c['ssh_endereco'] or '-'} "
                      f"-> {c['db_endereco']}:{c['db_porta'] or 5432}{marca}")
            return 0

        if a.abertos:
            for t in abertos():
                print(f"{t['id']:>3}  {t['cliente']:<24} "
                      f"127.0.0.1:{t['porta']} -> {t['destino']}  (pid {t['pid']})")
            return 0

        if a.porta_de:
            print(abrir(a.porta_de)["porta"])
            return 0

        if a.testar:
            print(json.dumps(testar(json.loads(sys.stdin.read())),
                             ensure_ascii=False))
            return 0

        if a.fechar_cliente:
            return 0 if fechar_cliente(a.fechar_cliente) else 1

        if a.fechar:
            return 0 if fechar(a.fechar) else 1

        print(json.dumps(abrir(a.abrir, a.porta), ensure_ascii=False))
        return 0
    except (RuntimeError, ValueError, cliente_ssh.SemChave) as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
