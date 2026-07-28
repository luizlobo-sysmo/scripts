# scripts

Rotinas compartilhadas entre os projetos em `D:\Lobo\Projetos\Claude`.

| arquivo | o que faz |
|---|---|
| `cliente_ssh.py` | lê e grava os acessos de cliente na base compartilhada; cifra e decifra as senhas |
| `tunel.py` | abre o túnel SSH até o banco do cliente, em porta local dinâmica |

Os dados ficam em `../db` (veja o README de lá): base SQLite `cliente_ssh.db` e a
chave de criptografia no `.env`. Nada de credencial neste repositório.

## Por que existem

O túnel e o cadastro de acesso eram implementados em cada lugar que precisava
deles — a skill `sysmo-devops` em Python, o backend do ProjecaoIA em Java. Duas
implementações do mesmo túnel divergem: em tratamento de host key, em como a senha
é passada, em qual porta é usada. Aqui é uma só, e quem precisa chama.

O backend Java, por exemplo, não implementa SSH: ele invoca `tunel.py` e lê a porta
que o script devolve em JSON.

## Uso

```bash
python tunel.py --listar                  # clientes cadastrados
python tunel.py --abrir cegil             # abre e devolve JSON com a porta
python tunel.py --porta cegil             # só a porta, abrindo se preciso
python tunel.py --abertos                 # túneis no ar
python tunel.py --fechar-cliente cegil
```

Como módulo:

```python
import cliente_ssh, tunel

c = cliente_ssh.por_nome("Cegil")          # senhas decifradas
porta = tunel.abrir("Cegil")["porta"]      # reaproveita se já estiver aberto
```

## Requisitos

- Python 3.10+
- `cryptography` (`pip install cryptography`) — AES-256-GCM das senhas
- `plink.exe` do PuTTY no Windows, ou `ssh` no Linux

O `plink.exe` é localizado dinamicamente: variável `PLINK`, depois `PATH`, depois os
diretórios usuais de instalação. Nenhum caminho fixo no código.

## Windows e WSL na mesma máquina

Rodando no WSL, o túnel é aberto por um binário **Windows** (`plink.exe`) quando
quem consome também é Windows. Motivo: o WSL2 em NAT tem loopback próprio, e um
túnel aberto pelo `ssh` do WSL não é alcançado do lado Windows.

Consequência prática: a conferência de "a porta subiu?" precisa ser feita pelo
Windows (`netstat` via `cmd.exe`). Um teste de socket feito de dentro do WSL nunca
vê o listener e faria a espera falhar mesmo com o túnel de pé.
