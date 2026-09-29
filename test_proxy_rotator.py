import asyncio
import base64
import unittest
from proxy_rotator import (
    ProxyNode,
    parse_proxy_string,
    ProxyRotatorServer,
)


class TestProxyParser(unittest.TestCase):
    def test_parse_http_url(self):
        p = parse_proxy_string("http://user:pass@127.0.0.1:8080")
        self.assertIsNotNone(p)
        self.assertEqual(p.protocol, "http")
        self.assertEqual(p.host, "127.0.0.1")
        self.assertEqual(p.port, 8080)
        self.assertEqual(p.username, "user")
        self.assertEqual(p.password, "pass")

    def test_parse_socks5_url(self):
        p = parse_proxy_string("socks5://admin:secret@proxy.com:1080")
        self.assertIsNotNone(p)
        self.assertEqual(p.protocol, "socks5")
        self.assertEqual(p.host, "proxy.com")
        self.assertEqual(p.port, 1080)
        self.assertEqual(p.username, "admin")
        self.assertEqual(p.password, "secret")

    def test_parse_scraper_format(self):
        p = parse_proxy_string("1.2.3.4:9999:myuser:mypass")
        self.assertIsNotNone(p)
        self.assertEqual(p.protocol, "http")
        self.assertEqual(p.host, "1.2.3.4")
        self.assertEqual(p.port, 9999)
        self.assertEqual(p.username, "myuser")
        self.assertEqual(p.password, "mypass")


class TestProxyRotatorIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []

    async def asyncTearDown(self):
        for s in self.servers:
            s.close()
            await s.wait_closed()

    async def create_echo_target(self, port: int):
        async def handle(r, w):
            data = await r.read(1024)
            w.write(b"ECHO:" + data)
            await w.drain()
            w.close()

        server = await asyncio.start_server(handle, "127.0.0.1", port)
        self.servers.append(server)
        return server

    async def create_mock_http_proxy(
        self, port: int, expected_auth: str, delay: float = 0, reject: bool = False
    ):
        async def handle(r, w):
            if delay > 0:
                await asyncio.sleep(delay)
            if reject:
                w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await w.drain()
                w.close()
                return

            req_line = await r.readline()
            headers = {}
            while True:
                line = await r.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                k, v = line.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()

            auth_hdr = headers.get("proxy-authorization", "")
            if expected_auth and auth_hdr != f"Basic {expected_auth}":
                w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                await w.drain()
                w.close()
                return

            w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await w.drain()

            # Conecta ao target
            target_parts = req_line.decode().split()[1].split(":")
            thost, tport = target_parts[0], int(target_parts[1])
            tr, tw = await asyncio.open_connection(thost, tport)

            async def pipe(src, dst):
                try:
                    while True:
                        d = await src.read(4096)
                        if not d:
                            break
                        dst.write(d)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    dst.close()

            await asyncio.gather(pipe(r, tw), pipe(tr, w))

        server = await asyncio.start_server(handle, "127.0.0.1", port)
        self.servers.append(server)
        return server

    async def test_rotation_timeout_and_fallback(self):
        target_port = 19100
        rotator_port = 19101
        proxy_fail_port = 19102
        proxy_timeout_port = 19103
        fallback_port = 19104

        await self.create_echo_target(target_port)
        # Proxy 1: Rejeita com 502
        await self.create_mock_http_proxy(proxy_fail_port, expected_auth="", reject=True)
        # Proxy 2: Lento (demora 2.5s, quando timeout é 0.5s)
        await self.create_mock_http_proxy(proxy_timeout_port, expected_auth="", delay=2.5)

        # Fallback Proxy: Funciona com autenticação
        auth_token = base64.b64encode(b"falluser:fallpass").decode()
        await self.create_mock_http_proxy(fallback_port, expected_auth=auth_token)

        proxies = [
            ProxyNode("raw", "http", "127.0.0.1", proxy_fail_port),
            ProxyNode("raw", "http", "127.0.0.1", proxy_timeout_port),
        ]
        fallback = ProxyNode(
            "raw", "http", "127.0.0.1", fallback_port, "falluser", "fallpass"
        )

        rotator = ProxyRotatorServer(
            listen_host="127.0.0.1",
            listen_port=rotator_port,
            timeout=0.6,
            proxies=proxies,
            fallback_proxy=fallback,
        )

        rotator_server = await asyncio.start_server(
            rotator.on_client_connected, "127.0.0.1", rotator_port
        )
        self.servers.append(rotator_server)

        # Cliente HTTP CONNECT
        cr, cw = await asyncio.open_connection("127.0.0.1", rotator_port)
        cw.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
        await cw.drain()

        resp_line = await cr.readline()
        self.assertIn(b"200 Connection Established", resp_line)
        # Consome headers
        while True:
            l = await cr.readline()
            if l in (b"\r\n", b"\n", b""):
                break

        # Envia dado através do túnel
        cw.write(b"HELLO_WORLD")
        await cw.drain()

        echo = await cr.read(1024)
        self.assertEqual(echo, b"ECHO:HELLO_WORLD")
        cw.close()
        await cw.wait_closed()

    async def create_mock_socks5_proxy(
        self, port: int, expected_user: str = "", expected_pass: str = ""
    ):
        async def handle(r, w):
            # Handshake
            hdr = await r.readexactly(2)
            nmethods = (await r.readexactly(hdr[1]))
            w.write(b"\x05\x02")  # requer user/pass
            await w.drain()

            # Auth
            auth_ver = (await r.readexactly(1))[0]
            ulen = (await r.readexactly(1))[0]
            uname = (await r.readexactly(ulen)).decode()
            plen = (await r.readexactly(1))[0]
            passwd = (await r.readexactly(plen)).decode()

            if uname == expected_user and passwd == expected_pass:
                w.write(b"\x01\x00")  # Sucesso
            else:
                w.write(b"\x01\x01")  # Falha
                await w.drain()
                w.close()
                return
            await w.drain()

            # Connect
            req = await r.readexactly(4)
            atyp = req[3]
            if atyp == 0x01:
                addr = (await r.readexactly(4))
                thost = "127.0.0.1"
            elif atyp == 0x03:
                dlen = (await r.readexactly(1))[0]
                thost = (await r.readexactly(dlen)).decode()
            port_b = await r.readexactly(2)
            tport = int.from_bytes(port_b, "big")

            tr, tw = await asyncio.open_connection(thost, tport)
            w.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            await w.drain()

            async def pipe(src, dst):
                try:
                    while True:
                        d = await src.read(4096)
                        if not d:
                            break
                        dst.write(d)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    dst.close()

            await asyncio.gather(pipe(r, tw), pipe(tr, w))

        server = await asyncio.start_server(handle, "127.0.0.1", port)
        self.servers.append(server)
        return server

    async def test_socks5_upstream_tunnel(self):
        target_port = 19200
        rotator_port = 19201
        socks_proxy_port = 19202

        await self.create_echo_target(target_port)
        await self.create_mock_socks5_proxy(socks_proxy_port, "socksuser", "sockspass")

        proxies = [
            ProxyNode("raw", "socks5", "127.0.0.1", socks_proxy_port, "socksuser", "sockspass")
        ]

        rotator = ProxyRotatorServer(
            listen_host="127.0.0.1",
            listen_port=rotator_port,
            timeout=2.0,
            proxies=proxies,
        )

        rotator_server = await asyncio.start_server(
            rotator.on_client_connected, "127.0.0.1", rotator_port
        )
        self.servers.append(rotator_server)

        # Cliente local conecta via HTTP CONNECT para o rotator, que encaminha para o proxy SOCKS5 upstream
        cr, cw = await asyncio.open_connection("127.0.0.1", rotator_port)
        cw.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
        await cw.drain()

        resp_line = await cr.readline()
        self.assertIn(b"200 Connection Established", resp_line)
        while True:
            l = await cr.readline()
            if l in (b"\r\n", b"\n", b""):
                break

        cw.write(b"SOCKS5_PING")
        await cw.drain()

        echo = await cr.read(1024)
        self.assertEqual(echo, b"ECHO:SOCKS5_PING")
        cw.close()
        await cw.wait_closed()

    async def test_concurrent_connections(self):
        target_port = 19300
        rotator_port = 19301
        proxy_port = 19302

        await self.create_echo_target(target_port)
        await self.create_mock_http_proxy(proxy_port, expected_auth="")

        proxies = [ProxyNode("raw", "http", "127.0.0.1", proxy_port)]
        rotator = ProxyRotatorServer(
            listen_host="127.0.0.1",
            listen_port=rotator_port,
            timeout=5.0,
            proxies=proxies,
        )
        rotator_server = await asyncio.start_server(
            rotator.on_client_connected, "127.0.0.1", rotator_port
        )
        self.servers.append(rotator_server)

        # Dispara 20 conexões simultâneas concorrentes
        async def single_client(idx: int):
            cr, cw = await asyncio.open_connection("127.0.0.1", rotator_port)
            cw.write(
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode()
            )
            await cw.drain()
            resp = await cr.readline()
            assert b"200 Connection Established" in resp
            while True:
                l = await cr.readline()
                if l in (b"\r\n", b"\n", b""):
                    break
            msg = f"CONCURRENT_TEST_{idx}".encode()
            cw.write(msg)
            await cw.drain()
            echo = await cr.read(1024)
            assert echo == b"ECHO:" + msg
            cw.close()
            await cw.wait_closed()
            return True

        results = await asyncio.gather(*(single_client(i) for i in range(20)))
        self.assertEqual(len(results), 20)
        self.assertTrue(all(results))

    async def test_local_authentication_http(self):
        target_port = 19400
        rotator_port = 19401
        proxy_port = 19402

        await self.create_echo_target(target_port)
        await self.create_mock_http_proxy(proxy_port, expected_auth="")

        proxies = [ProxyNode("raw", "http", "127.0.0.1", proxy_port)]
        rotator = ProxyRotatorServer(
            listen_host="127.0.0.1",
            listen_port=rotator_port,
            timeout=2.0,
            proxies=proxies,
            auth_user="localadmin",
            auth_pass="supersecret",
        )
        rotator_server = await asyncio.start_server(
            rotator.on_client_connected, "127.0.0.1", rotator_port
        )
        self.servers.append(rotator_server)

        # 1. Teste sem autenticação: Deve receber 407
        cr, cw = await asyncio.open_connection("127.0.0.1", rotator_port)
        cw.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
        await cw.drain()
        resp = await cr.readline()
        self.assertIn(b"407 Proxy Authentication Required", resp)
        cw.close()
        await cw.wait_closed()

        # 2. Teste com autenticação correta: Deve passar
        token = base64.b64encode(b"localadmin:supersecret").decode()
        cr, cw = await asyncio.open_connection("127.0.0.1", rotator_port)
        cw.write(
            f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n"
            f"Proxy-Authorization: Basic {token}\r\n\r\n".encode()
        )
        await cw.drain()
        resp = await cr.readline()
        self.assertIn(b"200 Connection Established", resp)
        while True:
            l = await cr.readline()
            if l in (b"\r\n", b"\n", b""):
                break
        cw.write(b"AUTH_OK")
        await cw.drain()
        echo = await cr.read(1024)
        self.assertEqual(echo, b"ECHO:AUTH_OK")
        cw.close()
        await cw.wait_closed()


if __name__ == "__main__":
    unittest.main()



