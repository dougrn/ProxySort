#!/usr/bin/env python3
"""
ProxySort - Proxy Rotator & TCP Dispatcher em Python
Recebe conexões locais (sem autenticação) e as redireciona para um proxy remoto
autenticado (HTTP/HTTPS ou SOCKS5) escolhido aleatoriamente de uma lista.

Possui:
- Timeout configurável por tentativa de conexão.
- Rotação aleatória sem repetição por requisição.
- Fallback automático caso todos os proxies da lista falhem.
- Suporte a clientes HTTP/HTTPS (CONNECT) e SOCKS5 na mesma porta.
- Suporte a modo Túnel TCP Bruto (para destinos fixos pré-configurados).
- Implementação assíncrona pura em Python (asyncio), sem dependências externas.
"""

import asyncio
import base64
import ipaddress
import json
import logging
import os
import random
import re
import sys
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ProxySort")


@dataclass
class ProxyNode:
    raw: str
    protocol: str  # 'http' ou 'socks5'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    def __str__(self) -> str:
        auth = f"{self.username}:***@" if self.username else ""
        return f"{self.protocol}://{auth}{self.host}:{self.port}"


def parse_proxy_string(proxy_str: str) -> Optional[ProxyNode]:
    """
    Interpreta formatos variados de proxy:
    - http://user:pass@host:port
    - socks5://user:pass@host:port
    - host:port:user:pass
    - host:port
    - socks5:host:port:user:pass
    """
    s = proxy_str.strip()
    if not s or s.startswith("#"):
        return None

    protocol = "http"
    if "://" in s:
        parsed = urllib.parse.urlsplit(s)
        proto_lower = parsed.scheme.lower()
        if "socks" in proto_lower:
            protocol = "socks5"
        else:
            protocol = "http"

        host = parsed.hostname
        port = parsed.port or (1080 if protocol == "socks5" else 8080)
        return ProxyNode(
            raw=s,
            protocol=protocol,
            host=host,
            port=port,
            username=parsed.username,
            password=parsed.password,
        )

    # Formato scraper tipo host:port:user:pass ou proto:host:port...
    parts = s.split(":")
    if parts[0].lower() in ("http", "https", "socks5", "socks4"):
        protocol = "socks5" if "socks" in parts[0].lower() else "http"
        parts = parts[1:]

    if len(parts) == 2:
        # host:port
        return ProxyNode(
            raw=s,
            protocol=protocol,
            host=parts[0],
            port=int(parts[1]),
        )
    elif len(parts) == 4:
        # host:port:user:pass
        return ProxyNode(
            raw=s,
            protocol=protocol,
            host=parts[0],
            port=int(parts[1]),
            username=parts[2],
            password=parts[3],
        )

    logger.warning(f"Formato de proxy desconhecido ignorado: {s}")
    return None


class UpstreamConnector:
    """Responsável por estabelecer túnel TCP através do proxy upstream (HTTP ou SOCKS5)."""

    @staticmethod
    async def connect_http(
        proxy: ProxyNode, target_host: str, target_port: int, timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout=timeout
        )

        headers = [
            f"CONNECT {target_host}:{target_port} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
            "Proxy-Connection: Keep-Alive",
            "User-Agent: ProxySort/1.0",
        ]

        if proxy.username and proxy.password:
            token = base64.b64encode(
                f"{proxy.username}:{proxy.password}".encode("utf-8")
            ).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {token}")

        headers_str = "\r\n".join(headers) + "\r\n\r\n"
        writer.write(headers_str.encode("latin1"))
        await writer.drain()

        # Ler resposta HTTP do CONNECT
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not status_line:
            writer.close()
            raise ConnectionError("Proxy fechou a conexão prematuramente.")

        parts = status_line.decode("latin1", errors="replace").split()
        if len(parts) < 2 or parts[1] != "200":
            writer.close()
            raise ConnectionError(
                f"Proxy HTTP recusou túnel: {status_line.decode('latin1', errors='replace').strip()}"
            )

        # Consumir o restante dos cabeçalhos até a linha em branco
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line or line in (b"\r\n", b"\n", b""):
                break

        return reader, writer

    @staticmethod
    async def connect_socks5(
        proxy: ProxyNode, target_host: str, target_port: int, timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout=timeout
        )

        # 1. Saudação SOCKS5
        if proxy.username and proxy.password:
            writer.write(b"\x05\x02\x00\x02")  # Suporta NO AUTH e USER/PASS
        else:
            writer.write(b"\x05\x01\x00")  # Apenas NO AUTH
        await writer.drain()

        greeting_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if greeting_resp[0] != 0x05:
            writer.close()
            raise ConnectionError("Resposta SOCKS inválida do servidor.")

        method = greeting_resp[1]
        if method == 0x02:
            # Autenticação por usuário e senha (RFC 1929)
            u_bytes = (proxy.username or "").encode("utf-8")
            p_bytes = (proxy.password or "").encode("utf-8")
            auth_payload = (
                b"\x01"
                + bytes([len(u_bytes)])
                + u_bytes
                + bytes([len(p_bytes)])
                + p_bytes
            )
            writer.write(auth_payload)
            await writer.drain()

            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth_resp[1] != 0x00:
                writer.close()
                raise ConnectionError(f"Autenticação SOCKS5 falhou (código {auth_resp[1]}).")
        elif method == 0x00:
            pass  # Nenhuma autenticação necessária
        else:
            writer.close()
            raise ConnectionError(f"Método de autenticação SOCKS5 não suportado ({method}).")

        # 2. Requisição de Conexão CONNECT
        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version == 4:
                atyp = 0x01
                dst_addr = ip_obj.packed
            else:
                atyp = 0x04
                dst_addr = ip_obj.packed
        except ValueError:
            atyp = 0x03
            domain_bytes = target_host.encode("idna")
            dst_addr = bytes([len(domain_bytes)]) + domain_bytes

        req = b"\x05\x01\x00" + bytes([atyp]) + dst_addr + target_port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()

        # 3. Resposta de conexão SOCKS5
        resp_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if resp_hdr[0] != 0x05 or resp_hdr[1] != 0x00:
            writer.close()
            raise ConnectionError(f"SOCKS5 CONNECT rejeitado (código {resp_hdr[1]}).")

        resp_atyp = resp_hdr[3]
        if resp_atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif resp_atyp == 0x03:
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=timeout)
        elif resp_atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)

        return reader, writer

    @classmethod
    async def connect(
        cls, proxy: ProxyNode, target_host: str, target_port: int, timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if proxy.protocol == "socks5":
            return await cls.connect_socks5(proxy, target_host, target_port, timeout)
        return await cls.connect_http(proxy, target_host, target_port, timeout)


class ProxyRotatorServer:
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        timeout: float = 4.0,
        proxies: Optional[List[ProxyNode]] = None,
        fallback_proxy: Optional[ProxyNode] = None,
        raw_target: Optional[Tuple[str, int]] = None,
        auth_user: Optional[str] = None,
        auth_pass: Optional[str] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.timeout = timeout
        self.proxies: List[ProxyNode] = proxies or []
        self.fallback_proxy = fallback_proxy
        self.raw_target = raw_target
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.server: Optional[asyncio.Server] = None

    async def get_upstream_connection(
        self, target_host: str, target_port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, ProxyNode]:
        """
        Tenta proxies da lista em ordem aleatória sem repetição.
        Se todos falharem ou expirarem o timeout, tenta o fallback.
        """
        candidates = list(self.proxies)
        random.shuffle(candidates)

        for candidate in candidates:
            try:
                reader, writer = await UpstreamConnector.connect(
                    candidate, target_host, target_port, self.timeout
                )
                return reader, writer, candidate
            except Exception as e:
                logger.warning(
                    f"Proxy {candidate} falhou [{type(e).__name__}: {e}]. Tentando próximo..."
                )

        # Se todos os candidatos da lista falharem, tentar o fallback
        if self.fallback_proxy:
            logger.info(
                f"Todos os {len(candidates)} proxies falharam. Acionando fallback: {self.fallback_proxy}"
            )
            try:
                reader, writer = await UpstreamConnector.connect(
                    self.fallback_proxy, target_host, target_port, self.timeout
                )
                return reader, writer, self.fallback_proxy
            except Exception as e:
                logger.error(
                    f"Proxy de fallback {self.fallback_proxy} também falhou [{type(e).__name__}: {e}]."
                )

        raise ConnectionError("Todos os proxies disponíveis e o fallback falharam.")

    @staticmethod
    async def bridge_streams(
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        remote_r: asyncio.StreamReader,
        remote_w: asyncio.StreamWriter,
    ):
        """Transfere dados bidirecionalmente entre o cliente local e o proxy remoto."""

        async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as err:
                logger.debug(f"Pipe error: {err}")
            finally:
                try:
                    if not writer.is_closing():
                        writer.close()
                except Exception:
                    pass

        task1 = asyncio.create_task(pipe(client_r, remote_w))
        task2 = asyncio.create_task(pipe(remote_r, client_w))

        # Quando uma ponta fechar, cancelamos a outra
        done, pending = await asyncio.wait(
            [task1, task2], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()

    async def handle_socks5_client(
        self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter
    ):
        """Gerencia conexões de clientes locais usando SOCKS5 (com ou sem autenticação)."""
        # Lê nmethods
        nmethods_b = await client_r.readexactly(1)
        nmethods = nmethods_b[0]
        methods = await client_r.readexactly(nmethods)

        # Autenticação de entrada (RFC 1929) se configurada
        if self.auth_user and self.auth_pass:
            if 0x02 not in methods:
                client_w.write(b"\x05\xff")  # Nenhum método aceitável
                await client_w.drain()
                client_w.close()
                return

            client_w.write(b"\x05\x02")  # Requer usuário e senha
            await client_w.drain()

            auth_ver = (await client_r.readexactly(1))[0]
            ulen = (await client_r.readexactly(1))[0]
            uname = (await client_r.readexactly(ulen)).decode("utf-8", errors="replace")
            plen = (await client_r.readexactly(1))[0]
            passwd = (await client_r.readexactly(plen)).decode("utf-8", errors="replace")

            if uname != self.auth_user or passwd != self.auth_pass:
                logger.warning(f"[SOCKS5] Falha de autenticação local: usuário '{uname}' incorreto.")
                client_w.write(b"\x01\x01")  # Falha
                await client_w.drain()
                client_w.close()
                return

            client_w.write(b"\x01\x00")  # Sucesso
            await client_w.drain()
        else:
            # Responde que nenhuma autenticação é necessária localmente
            client_w.write(b"\x05\x00")
            await client_w.drain()

        # Lê requisição de conexão do cliente
        req_hdr = await client_r.readexactly(4)
        cmd = req_hdr[1]
        atyp = req_hdr[3]

        if cmd != 0x01:  # Apenas comando CONNECT é suportado
            client_w.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            client_w.close()
            return

        if atyp == 0x01:  # IPv4
            addr_bytes = await client_r.readexactly(4)
            target_host = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == 0x03:  # Nome de domínio
            dlen = (await client_r.readexactly(1))[0]
            domain_bytes = await client_r.readexactly(dlen)
            target_host = domain_bytes.decode("utf-8", errors="replace")
        elif atyp == 0x04:  # IPv6
            addr_bytes = await client_r.readexactly(16)
            target_host = str(ipaddress.IPv6Address(addr_bytes))
        else:
            client_w.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            client_w.close()
            return

        port_bytes = await client_r.readexactly(2)
        target_port = int.from_bytes(port_bytes, "big")

        logger.info(f"[SOCKS5] Cliente solicitou túnel para {target_host}:{target_port}")

        try:
            remote_r, remote_w, used_proxy = await self.get_upstream_connection(
                target_host, target_port
            )
            logger.info(
                f"[SOCKS5] Conectado a {target_host}:{target_port} via proxy {used_proxy}"
            )
            # Notifica o cliente de sucesso
            client_w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_w.drain()
            await self.bridge_streams(client_r, client_w, remote_r, remote_w)
        except Exception as e:
            logger.error(f"[SOCKS5] Falha ao conectar a {target_host}:{target_port}: {e}")
            try:
                client_w.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # Host unreachable
                await client_w.drain()
            except Exception:
                pass
            client_w.close()

    async def handle_http_client(
        self,
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        first_line: str,
    ):
        """Gerencia conexões de clientes locais HTTP (CONNECT para HTTPS ou requisição direta)."""
        parts = first_line.split()
        if len(parts) < 2:
            client_w.close()
            return

        method = parts[0].upper()
        target = parts[1]

        # Consome cabeçalhos do cliente e valida Proxy-Authorization se configurada
        client_headers = []
        auth_header = None
        while True:
            line = await client_r.readline()
            if not line or line in (b"\r\n", b"\n", b""):
                break
            if line.lower().startswith(b"proxy-authorization:"):
                auth_header = line.decode("latin1", errors="replace").split(":", 1)[1].strip()
            else:
                client_headers.append(line)

        if self.auth_user and self.auth_pass:
            expected_token = base64.b64encode(
                f"{self.auth_user}:{self.auth_pass}".encode("utf-8")
            ).decode("ascii")
            if auth_header != f"Basic {expected_token}":
                logger.warning("[HTTP] Falha de autenticação local: credenciais ausentes ou inválidas.")
                err_auth = (
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"ProxySort\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                try:
                    client_w.write(err_auth)
                    await client_w.drain()
                except Exception:
                    pass
                client_w.close()
                return

        if method == "CONNECT":
            # HTTPS Tunneling
            if ":" in target:
                target_host, port_str = target.split(":", 1)
                target_port = int(port_str)
            else:
                target_host = target
                target_port = 443

            logger.info(f"[HTTP CONNECT] Cliente solicitou túnel para {target_host}:{target_port}")

            try:
                remote_r, remote_w, used_proxy = await self.get_upstream_connection(
                    target_host, target_port
                )
                logger.info(
                    f"[HTTP CONNECT] Conectado a {target_host}:{target_port} via proxy {used_proxy}"
                )
                client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_w.drain()
                await self.bridge_streams(client_r, client_w, remote_r, remote_w)
            except Exception as e:
                logger.error(
                    f"[HTTP CONNECT] Falha ao conectar a {target_host}:{target_port}: {e}"
                )
                err_resp = (
                    b"HTTP/1.1 504 Gateway Timeout\r\n"
                    b"Content-Type: text/plain\r\n\r\n"
                    b"Erro: Todos os proxies upstream falharam.\r\n"
                )
                try:
                    client_w.write(err_resp)
                    await client_w.drain()
                except Exception:
                    pass
                client_w.close()
        else:
            # Requisição HTTP simples (ex: GET http://site.com/path)
            parsed = urllib.parse.urlsplit(target)
            target_host = parsed.hostname or "127.0.0.1"
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # Reconstrói a requisição sem cabeçalho proxy-authorization local
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            reconstructed_request = [f"{method} {path} {parts[2]}".encode("latin1")]
            reconstructed_request.extend(client_headers)

            full_payload = b"\r\n".join(
                [l.rstrip(b"\r\n") for l in reconstructed_request]
            ) + b"\r\n\r\n"

            try:
                remote_r, remote_w, used_proxy = await self.get_upstream_connection(
                    target_host, target_port
                )
                # Envia a requisição do cliente diretamente no túnel
                remote_w.write(full_payload)
                await remote_w.drain()
                await self.bridge_streams(client_r, client_w, remote_r, remote_w)
            except Exception as e:
                logger.error(f"[HTTP] Falha na requisição para {target_host}:{target_port}: {e}")
                err_resp = (
                    b"HTTP/1.1 504 Gateway Timeout\r\n"
                    b"Content-Type: text/plain\r\n\r\n"
                    b"Erro: Todos os proxies upstream falharam.\r\n"
                )
                try:
                    client_w.write(err_resp)
                    await client_w.drain()
                except Exception:
                    pass
                client_w.close()

    async def handle_raw_tcp_client(
        self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter
    ):
        """Modo de túnel TCP fixo para destino pré-configurado."""
        target_host, target_port = self.raw_target
        logger.info(f"[RAW TCP] Encaminhando conexão direta para {target_host}:{target_port}")
        try:
            remote_r, remote_w, used_proxy = await self.get_upstream_connection(
                target_host, target_port
            )
            logger.info(
                f"[RAW TCP] Conectado a {target_host}:{target_port} via proxy {used_proxy}"
            )
            await self.bridge_streams(client_r, client_w, remote_r, remote_w)
        except Exception as e:
            logger.error(f"[RAW TCP] Falha ao encaminhar: {e}")
            client_w.close()

    async def on_client_connected(
        self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter
    ):
        """Ponto de entrada para novas conexões locais TCP."""
        try:
            # Caso o modo de destino TCP fixo esteja ativo:
            if self.raw_target:
                await self.handle_raw_tcp_client(client_r, client_w)
                return

            # Detecção automática do protocolo (SOCKS5 ou HTTP)
            first_byte = await client_r.read(1)
            if not first_byte:
                client_w.close()
                return

            if first_byte == b"\x05":
                # Cliente SOCKS5
                await self.handle_socks5_client(client_r, client_w)
            else:
                # Cliente HTTP ou CONNECT
                rest_of_line = await client_r.readline()
                first_line = (first_byte + rest_of_line).decode("latin1", errors="replace").strip()
                await self.handle_http_client(client_r, client_w, first_line)
        except Exception as e:
            logger.debug(f"Erro ao tratar cliente: {e}")
            try:
                client_w.close()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(
            self.on_client_connected, self.listen_host, self.listen_port
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"ProxySort rodando em {addrs}")
        logger.info(f"Total de proxies na lista: {len(self.proxies)}")
        logger.info(f"Timeout por tentativa: {self.timeout}s")
        if self.fallback_proxy:
            logger.info(f"Proxy de Fallback ativo: {self.fallback_proxy}")
        if self.auth_user and self.auth_pass:
            logger.info(f"Autenticação Local ativa para o usuário: '{self.auth_user}'")
        else:
            logger.info("Autenticação Local desativada (porta aberta sem senha).")
        if self.raw_target:
            logger.info(f"Modo Túnel TCP Fixo ativo para: {self.raw_target[0]}:{self.raw_target[1]}")
        else:
            logger.info("Modo Inteligente ativo: suporta HTTP/HTTPS CONNECT e SOCKS5 dinâmico.")

        async with self.server:
            await self.server.serve_forever()


def load_proxies_from_file(filepath: str) -> List[ProxyNode]:
    proxies = []
    if not os.path.exists(filepath):
        logger.warning(f"Arquivo de proxies '{filepath}' não encontrado.")
        return proxies

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            node = parse_proxy_string(line)
            if node:
                proxies.append(node)
    return proxies


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ProxySort - Proxy Rotator & TCP Dispatcher com Fallback e Timeout"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host/IP de escuta local (padrão: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Porta de escuta local (padrão: 8080)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Timeout em segundos para resposta do proxy (padrão: 4.0)",
    )
    parser.add_argument(
        "--auth",
        help="Autenticação na entrada local no formato usuario:senha (opcional)",
    )
    parser.add_argument(
        "--proxies-file",
        default="proxies.txt",
        help="Arquivo contendo a lista de proxies (padrão: proxies.txt)",
    )
    parser.add_argument(
        "--fallback",
        help="Proxy de fallback no caso de falha de todos da lista (ex: http://user:pass@host:port)",
    )
    parser.add_argument(
        "--target",
        help="Opcional: Destino fixo para modo TCP bruto no formato host:port (ex: 1.1.1.1:443)",
    )
    parser.add_argument(
        "--config", help="Arquivo de configuração JSON opcional"
    )

    args = parser.parse_args()

    listen_host = args.host
    listen_port = args.port
    timeout = args.timeout
    proxies_file = args.proxies_file
    fallback_str = args.fallback
    target_str = args.target
    auth_str = args.auth
    proxies_list: List[ProxyNode] = []

    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as cf:
            cfg = json.load(cf)
            listen_host = cfg.get("listen_host", listen_host)
            listen_port = cfg.get("listen_port", listen_port)
            timeout = cfg.get("timeout", timeout)
            auth_str = cfg.get("auth", auth_str)
            proxies_file = cfg.get("proxies_file", proxies_file)
            fallback_str = cfg.get("fallback_proxy", fallback_str)
            target_str = cfg.get("raw_target", target_str)
            for p in cfg.get("proxies", []):
                node = parse_proxy_string(p)
                if node:
                    proxies_list.append(node)

    # Carrega também do arquivo se existir
    if os.path.exists(proxies_file):
        file_proxies = load_proxies_from_file(proxies_file)
        proxies_list.extend(file_proxies)

    fallback_node = parse_proxy_string(fallback_str) if fallback_str else None

    auth_user, auth_pass = None, None
    if auth_str and ":" in auth_str:
        auth_user, auth_pass = auth_str.split(":", 1)

    raw_target = None
    if target_str and ":" in target_str:
        th, tp = target_str.split(":", 1)
        raw_target = (th, int(tp))

    if not proxies_list and not fallback_node:
        logger.warning(
            "Nenhum proxy fornecido na lista nem fallback. O servidor aguardará conexões, mas todas irão falhar até configurar os proxies."
        )

    server = ProxyRotatorServer(
        listen_host=listen_host,
        listen_port=listen_port,
        timeout=timeout,
        proxies=proxies_list,
        fallback_proxy=fallback_node,
        raw_target=raw_target,
        auth_user=auth_user,
        auth_pass=auth_pass,
    )

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("ProxySort encerrado pelo usuário.")


if __name__ == "__main__":
    main()
