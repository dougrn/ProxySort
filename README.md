<div align="center">

# ⚡ ProxySort

**Proxy Rotator & TCP Dispatcher de Alta Performance em Python Puro**

*Um gateway local inteligente, assíncrono e resiliente que distribui tráfego TCP entre proxies remotos autenticados (HTTP/SOCKS5) com rotação aleatória, timeout rígido e fallback automático.*

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-asyncio-green.svg)](https://docs.python.org/3/library/asyncio.html)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## 📖 Visão Geral

Ao trabalhar com web scraping em larga escala, bots, automações ou balanceamento de rede, é comum contratar pools de proxies autenticados (BrightData, Oxylabs, Smartproxy, IPRoyal, etc.). No entanto, ferramentas e scripts locais frequentemente enfrentam problemas graves:

- Proxies que travam ou demoram dezenas de segundos para responder, congelando scrapers;
- Dificuldade para rotacionar proxies diferentes a cada conexão sem reiniciar o cliente;
- Falhas totais de requisição quando um proxy da lista morre;
- Necessidade de usar bibliotecas pesadas e difíceis de configurar.

O **ProxySort** resolve esses problemas atuando como um **gateway intermediário leve e ultrarrápido** na sua máquina local ou servidor:
Você aponta seu scraper/navegador para `127.0.0.1:8080`, e o ProxySort se encarrega de selecionar aleatoriamente proxies da sua lista, aplicar um timeout estrito por tentativa, saltar proxies inoperantes e acionar um fallback seguro caso todos falhem.

---

## 🏗️ Arquitetura

```mermaid
flowchart TD
    subgraph Clientes ["Clientes Locais (Conexões Simultâneas)"]
        C1["Scraper / Bot (Python / Node)"]
        C2["cURL / API Client"]
        C3["Browser (Puppeteer / Playwright)"]
    end

    subgraph Core ["ProxySort Gateway (127.0.0.1:8080)"]
        GW["asyncio Event Loop<br/>(Detecção Auto: HTTP CONNECT / SOCKS5 / Raw TCP)"]
        AUTH{"Autenticação<br/>na Entrada?"}
        POOL["Pool de Tentativas<br/>(Shuffle sem repetição)"]
        TIMER["Timeout Monitor<br/>(ex: 4.0s por tentativa)"]
    end

    subgraph Upstream ["Proxies Remotos Autenticados"]
        P1["Proxy HTTP/HTTPS #1<br/>(user:pass@host:port)"]
        P2["Proxy SOCKS5 #2<br/>(user:pass@host:port)"]
        P3["Proxy Lento / Offline (Timeout)"]
        FALLBACK["Proxy de Fallback<br/>(Contingência Garantida)"]
    end

    subgraph Internet ["Destino"]
        DEST["Websites / APIs / Destino TCP"]
    end

    C1 & C2 & C3 --> GW
    GW --> AUTH
    AUTH -- "Válido / Desativado" --> POOL
    POOL --> TIMER
    TIMER -- "Tentativa 1 (Falha/Timeout)" --> P3
    P3 -.-> |"Salta para o próximo"| TIMER
    TIMER -- "Tentativa 2 (Sucesso)" --> P1 & P2
    TIMER -- "Se todos falharem" --> FALLBACK
    P1 & P2 & FALLBACK --> DEST
```

---

## ✨ Recursos Destacados

- ⚡ **Zero Dependências Externas**: Criado 100% com a biblioteca padrão do Python (`asyncio`, `urllib`, `base64`, `ipaddress`). Instalação instantânea sem precisar de `pip install`.
- 🚀 **Alta Concorrência Assíncrona**: Baseado em corrotinas não-bloqueantes. Suporta centenas de conexões simultâneas consumindo o mínimo de memória RAM e CPU.
- ⏱️ **Timeout Rígido por Tentativa**: Se um proxy demorar mais que o tempo configurado (ex: `3.0s`), ele é abortado imediatamente e o próximo é chamado, garantindo agilidade no seu pipeline.
- 🔀 **Rotação Aleatória sem Repetição**: Para cada requisição, a lista é embaralhada de forma independente. Proxies que falharem na requisição atual não são re-tentados nela.
- 🛡️ **Proxy de Fallback**: Um proxy de segurança garantido é acionado caso todos os proxies da lista principal fiquem fora do ar.
- 🔄 **Suporte Dual Upstream**: Conecta nativamente em proxies **HTTP/HTTPS** (Basic Auth) e **SOCKS5** (RFC 1929 Auth).
- 🔌 **Detecção Automática na Entrada**: Aceita tanto clientes locais HTTP/HTTPS (`CONNECT`) quanto clientes SOCKS5 na mesma porta de escuta.
- 🔒 **Autenticação Opcional na Entrada (`--auth`)**: Permite proteger a porta local caso você hospede o ProxySort em uma VPS pública. Suas senhas locais nunca são vazadas para o proxy remoto.
- 🎯 **Modo Túnel TCP Fixo (`--target`)**: Opção para encaminhar tráfego TCP bruto para um endereço fixo remoto através dos proxies rotacionados.

---

## 🚀 Instalação e Início Rápido

### Pré-requisitos
- Python 3.8 ou superior instalado.

### 1. Clonar o repositório
```bash
git clone https://github.com/dougrn/ProxySort.git
cd ProxySort
```

### 2. Configurar seus Proxies
Crie um arquivo `proxies.txt` com a sua lista (um proxy por linha). O ProxySort suporta formatos variados:

```text
# proxies.txt
http://usuario1:senha1@proxy1.exemplo.com:8080
socks5://usuario2:senha2@proxy2.exemplo.com:1080
185.120.30.40:3128:meu_usuario:minha_senha
192.168.1.100:8080
```

*(Consulte [`proxies.example.txt`](proxies.example.txt) para mais modelos).*

### 3. Executar o Servidor
```bash
python proxy_rotator.py --port 8080 --timeout 4.0 --fallback "http://backup_user:backup_pass@proxy-backup.com:8080"
```

Pronto! Seu dispatcher de proxies já está ativo em `http://127.0.0.1:8080`.

---

## ⚙️ Opções de Linha de Comando (CLI)

| Opção | Padrão | Descrição |
| :--- | :---: | :--- |
| `--host` | `0.0.0.0` | Endereço IP de escuta local. |
| `--port` | `8080` | Porta TCP local onde o ProxySort aguardará conexões. |
| `--timeout` | `4.0` | Timeout máximo (em segundos) para resposta de cada proxy upstream. |
| `--auth` | `None` | Autenticação local exigida para clientes (`usuario:senha`). Opcional. |
| `--proxies-file` | `proxies.txt` | Caminho do arquivo contendo a lista de proxies. |
| `--fallback` | `None` | Proxy de contingência usado se todos os proxies da lista falharem. |
| `--target` | `None` | Destino fixo no formato `host:port` para modo túnel TCP direto. |
| `--config` | `None` | Caminho de um arquivo de configuração JSON. |

---

## 📄 Configuração via `config.json`

Você também pode gerenciar suas opções por um arquivo centralizado:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 8080,
  "timeout": 4.0,
  "auth": null,
  "proxies_file": "proxies.txt",
  "fallback_proxy": "http://backup_user:backup_pass@backup-proxy.com:8080",
  "raw_target": null,
  "proxies": [
    "http://user1:pass1@1.2.3.4:8080",
    "socks5://user2:pass2@5.6.7.8:1080"
  ]
}
```

Para iniciar com o arquivo de configuração:
```bash
python proxy_rotator.py --config config.json
```

---

## 💻 Exemplos de Integração com Clientes

### 1. cURL

```bash
# Requisição simples através do proxy local
curl -x http://127.0.0.1:8080 https://api.ipify.org?format=json

# Com autenticação na porta local (se você configurou --auth user:pass)
curl -U "user:pass" -x http://127.0.0.1:8080 https://api.ipify.org?format=json
```

---

### 2. Python (`requests` / `httpx`)

```python
import requests

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Se configurou autenticação de entrada (--auth admin:senha123):
# proxies = {"http": "http://admin:senha123@127.0.0.1:8080", "https": "http://admin:senha123@127.0.0.1:8080"}

res = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
print("IP Recebido:", res.json())
```

---

### 3. Node.js (Puppeteer / Playwright)

```javascript
// Exemplo com Playwright
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({
    proxy: {
      server: 'http://127.0.0.1:8080',
      // username: 'admin', // Se --auth estiver ativo
      // password: 'senha123'
    }
  });
  const page = await browser.newPage();
  await page.goto('https://api.ipify.org?format=json');
  console.log(await page.textContent('body'));
  await browser.close();
})();
```

---

### 4. Modo Túnel TCP Fixo (`--target`)

Se você possui um serviço que utiliza um protocolo TCP arbitrário (como conexões de banco de dados, IRC, SSH ou APIs customizadas) e quer que cada conexão TCP passe por um proxy rotacionado:

```bash
python proxy_rotator.py --port 9000 --target meu-servidor-remoto.com:443 --timeout 3.0
```
Qualquer cliente conectando em `127.0.0.1:9000` será roteado para `meu-servidor-remoto.com:443` por meio de um proxy aleatório da sua lista!

---

## 🧪 Testes Automatizados

O repositório já inclui uma suíte completa de testes de integração ([`test_proxy_rotator.py`](test_proxy_rotator.py)) que sobe instâncias locais de teste mockando:
- Proxies HTTP com falhas propositais (`HTTP 502`);
- Proxies com lentidão induzida para validar o descarte por timeout;
- Proxies SOCKS5 autenticados;
- Ativação do fallback quando a lista se esgota;
- Validação de 20 conexões simultâneas concorrentes;
- Validação de autenticação de entrada HTTP e SOCKS5.

Para rodar todos os testes:
```bash
python -m unittest test_proxy_rotator.py
```

Resultado esperado:
```text
Ran 7 tests in ~10s
OK
```

---

## 🔒 Segurança

- **Proteção de Credenciais**: O arquivo `.gitignore` já vem configurado para evitar que listas privadas (`proxies.txt`) e arquivos de ambiente (`.env`) sejam enviados por acidente para o repositório.
- **Isolamento de Cabeçalhos**: Quando a autenticação local (`--auth`) é utilizada, o cabeçalho de credencial local é filtrado e descartado internamente, garantindo que suas senhas locais jamais sejam transmitidas aos servidores ou proxies upstream.

---

## 🤝 Contribuição

Contribuições são super bem-vindas! Sinta-se à vontade para abrir uma *Issue* ou enviar um *Pull Request*:

1. Faça um Fork do projeto
2. Crie uma branch para a sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Faça commit das alterações (`git commit -m 'feat: adiciona nova funcionalidade'`)
4. Envie para o branch remoto (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

---

## 📜 Licença

Distribuído sob a licença **MIT**. Consulte o arquivo [`LICENSE`](LICENSE) para obter mais informações.
