#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, struct, hashlib, base64, asyncio, logging, ipaddress
import platform
import urllib.request
import importlib.util
import aiohttp
from aiohttp import web

# ==================== 环境变量 ====================
UUID = os.environ.get('UUID') or 'c202b33e-03d9-406c-9bba-1ca228036028'
SUB_PATH = os.environ.get('SUB_PATH') or 'sub'
NAME = os.environ.get('NAME') or ''
WSPATH = os.environ.get('WSPATH') or UUID[:8]
PORT = int(os.environ.get('PORT') or 3000)
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# 模板模式：由 create_args 注入，触发预热 + 写 template_instance
TEMPLATE_MODE = os.environ.get('TEMPLATE_MODE', '').lower() == 'true'

# 哪吒 Agent
NZ_SERVER = os.environ.get('NZ_SERVER') or os.environ.get('SERVER') or ''
NZ_CLIENT_SECRET = os.environ.get('NZ_CLIENT_SECRET') or os.environ.get('CLIENT_SECRET') or ''
NZ_UUID = os.environ.get('NZ_UUID') or UUID
ENABLE_NEZHA = os.environ.get('ENABLE_NEZHA', 'false').lower() == 'true'

SUB_DOMAIN_PORT = 443
INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
TEMPLATE_INSTANCE_PATH = '/uk/libukp/template_instance'

# ==================== 日志 ====================
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("app")
logger.setLevel(log_level)
for noisy in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client',
              'aiohttp.internal', 'aiohttp.websocket'):
    logging.getLogger(noisy).setLevel(logging.WARNING)

# ==================== 常量 ====================
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com',
    'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io',
    'librespeed.org', 'speedcheck.org'
]

# ==================== 工具函数 ====================
def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)


async def get_isp() -> str:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get('https://api.ip.sb/geoip',
                             headers={'User-Agent': 'Mozilla/5.0'},
                             timeout=3) as r:
                if r.status == 200:
                    d = await r.json()
                    return f"{d.get('country_code', '')}-{d.get('isp', '')}".replace(' ', '_')
    except Exception:
        pass
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get('http://ip-api.com/json',
                             headers={'User-Agent': 'Mozilla/5.0'},
                             timeout=3) as r:
                if r.status == 200:
                    d = await r.json()
                    return f"{d.get('countryCode', '')}-{d.get('org', '')}".replace(' ', '_')
    except Exception:
        pass
    return 'Unknown'


async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    for _ in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as s:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with s.get(url, timeout=5) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for a in data['Answer']:
                                if a.get('type') == 1:
                                    return a.get('data')
        except Exception:
            continue
    return host


# ==================== 代理处理器 ====================
class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)

    async def _pipe(self, websocket, reader, writer):
        async def ws_to_tcp():
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        async def tcp_to_ws():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except Exception:
                pass

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.uuid_bytes:
                return False

            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False

            port = struct.unpack('!H', first_msg[i:i + 2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1

            host = ''
            if atyp == 1:
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i + 4]); i += 4
            elif atyp == 2:
                if i >= len(first_msg):
                    return False
                hl = first_msg[i]; i += 1
                if i + hl > len(first_msg):
                    return False
                host = first_msg[i:i + hl].decode(); i += hl
            elif atyp == 3:
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j]<<8)+first_msg[j+1]:04x}'
                                for j in range(i, i+16, 2))
                i += 16
            else:
                return False

            if is_blocked_domain(host):
                await websocket.close(); return False

            await websocket.send_bytes(bytes([0, 0]))

            try:
                reader, writer = await asyncio.open_connection(
                    await resolve_host(host), port)
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()
                await self._pipe(websocket, reader, writer)
            except Exception as e:
                if DEBUG: logger.error(f"VLESS conn error: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"VLESS handler error: {e}")
            return False

    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 58:
                return False

            received = first_msg[:56].decode('ascii', errors='ignore')
            h1 = hashlib.sha224(self.uuid.encode()).hexdigest()
            h2 = hashlib.sha224(UUID.encode()).hexdigest()
            if received != h1 and received != h2:
                return False

            offset = 56
            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2
            if first_msg[offset] != 1:
                return False
            offset += 1
            atyp = first_msg[offset]; offset += 1

            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[offset:offset + 4]); offset += 4
            elif atyp == 3:
                hl = first_msg[offset]; offset += 1
                host = first_msg[offset:offset + hl].decode(); offset += hl
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j]<<8)+first_msg[j+1]:04x}'
                                for j in range(offset, offset + 16, 2))
                offset += 16
            else:
                return False

            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2
            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2

            if is_blocked_domain(host):
                await websocket.close(); return False

            try:
                reader, writer = await asyncio.open_connection(
                    await resolve_host(host), port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                await self._pipe(websocket, reader, writer)
            except Exception as e:
                if DEBUG: logger.error(f"Trojan conn error: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"Trojan handler error: {e}")
            return False

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7:
                return False
            offset = 0
            atyp = first_msg[offset]; offset += 1

            if atyp == 1:
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset + 4]); offset += 4
            elif atyp == 3:
                hl = first_msg[offset]; offset += 1
                if offset + hl > len(first_msg):
                    return False
                host = first_msg[offset:offset + hl].decode(); offset += hl
            elif atyp == 4:
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j]<<8)+first_msg[j+1]:04x}'
                                for j in range(offset, offset + 16, 2))
                offset += 16
            else:
                return False

            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2

            if is_blocked_domain(host):
                await websocket.close(); return False

            try:
                reader, writer = await asyncio.open_connection(
                    await resolve_host(host), port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                await self._pipe(websocket, reader, writer)
            except Exception as e:
                if DEBUG: logger.error(f"SS conn error: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"SS handler error: {e}")
            return False


# ==================== HTTP / WebSocket ====================
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if f'/{WSPATH}' not in request.path:
        await ws.close(); return ws

    proxy = ProxyHandler(UUID.replace('-', ''))
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close(); return ws
        data = first_msg.data

        if len(data) > 17 and data[0] == 0:
            if await proxy.handle_vless(ws, data):
                return ws
        if len(data) >= 58:
            if await proxy.handle_trojan(ws, data):
                return ws
        if data and data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, data):
                return ws

        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG: logger.error(f"WS error: {e}")
        await ws.close()
    return ws


async def http_handler(request):
    if request.path == '/':
        try:
            with open(INDEX_HTML, 'r', encoding='utf-8') as f:
                return web.Response(text=f.read(), content_type='text/html')
        except FileNotFoundError:
            return web.Response(text='Hello world!', content_type='text/html')

    if request.path == '/__meta':
        return web.json_response({
            'uuid': UUID,
            'wspath': WSPATH,
            'subpath': SUB_PATH,
            'name': NAME,
        })

    if request.path == f'/{SUB_PATH}':
        isp = await get_isp()
        domain = request.host.split(':')[0]
        port = SUB_DOMAIN_PORT
        name_part = f"{NAME}-{isp}" if NAME else isp

        vless = (
            f"vless://{UUID}@{domain}:{port}"
            f"?encryption=none&security=tls&sni={domain}"
            f"&fp=chrome&type=ws&host={domain}"
            f"&path=%2F{WSPATH}#{name_part}"
        )
        trojan = (
            f"trojan://{UUID}@{domain}:{port}"
            f"?security=tls&sni={domain}"
            f"&fp=chrome&type=ws&host={domain}"
            f"&path=%2F{WSPATH}#{name_part}"
        )
        ss_pwd = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss = (
            f"ss://{ss_pwd}@{domain}:{port}"
            f"?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{domain};"
            f"path%3D%2F{WSPATH};tls;sni%3D{domain};"
            f"skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        )

        sub = f"{vless}\n{trojan}\n{ss}"
        b64 = base64.b64encode(sub.encode()).decode()
        return web.Response(text=b64 + '\n', content_type='text/plain')

    return web.Response(status=404, text='Not Found\n')


# ==================== 哪吒 Agent ====================
def _get_python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def _get_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported arch: {m}")


def _download_agent_so() -> bool:
    try:
        py_ver = _get_python_version()
        arch = _get_arch()
        asset_name = f"main-{py_ver}-{arch}-musl.so"

        api_url = "https://api.github.com/repos/oyz8/agent-v1-so/releases/latest"
        with urllib.request.urlopen(api_url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            tag = data.get("tag_name")
            if not tag:
                logger.error("No tag_name in response")
                return False

        assets = data.get("assets", [])
        matched = next((a for a in assets if a.get("name") == asset_name), None)
        if matched:
            dl = matched.get("browser_download_url")
        else:
            dl = f"https://github.com/oyz8/agent-v1-so/releases/download/{tag}/{asset_name}"

        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.so")
        logger.info(f"Downloading {asset_name}")
        urllib.request.urlretrieve(dl, local)
        return True
    except Exception as e:
        logger.error(f"Download failed: {e}")
        return False


def _start_nezha_sync() -> bool:
    try:
        logger.info(f"Nezha: SERVER={NZ_SERVER}, UUID={NZ_UUID}")
        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.so")
        if not os.path.exists(local):
            if not _download_agent_so():
                return False

        spec = importlib.util.spec_from_file_location("main", local)
        if spec is None or spec.loader is None:
            return False
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        logger.info("main.so loaded")

        os.environ["NZ_SERVER"] = NZ_SERVER
        os.environ["NZ_CLIENT_SECRET"] = NZ_CLIENT_SECRET
        os.environ["NZ_UUID"] = NZ_UUID
        os.environ["SERVER"] = NZ_SERVER
        os.environ["CLIENT_SECRET"] = NZ_CLIENT_SECRET
        os.environ["UUID"] = NZ_UUID

        if hasattr(module, "WorkerApp"):
            logger.info("Using WorkerApp(config_path=None)")
            module.WorkerApp(config_path=None).run()
        elif hasattr(module, "start_worker"):
            logger.info("Using start_worker(config)")
            asyncio.run(module.start_worker({
                "server": NZ_SERVER,
                "secret": NZ_CLIENT_SECRET,
                "uuid": NZ_UUID,
            }))
        else:
            logger.error("main.so has no WorkerApp/start_worker")
            return False
        return True
    except Exception as e:
        import traceback
        logger.error(f"Nezha failed: {e}")
        logger.error(traceback.format_exc())
        return False


async def _schedule_nezha():
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _start_nezha_sync)
    except Exception as e:
        logger.error(f"Nezha schedule error: {e}")


# ==================== 预热 ====================
def _warmup_aiohttp():
    """预热 aiohttp 及其所有 C 扩展，让快照包含已加载状态。"""
    import aiohttp
    from aiohttp import web
    import aiohttp.resolver
    import aiohttp.web_ws
    import aiohttp.connector

    # 主动触发各模块的初始化
    _ = aiohttp.ClientSession
    _ = aiohttp.TCPConnector
    _ = aiohttp.resolver.DefaultResolver
    _ = aiohttp.web_ws.WebSocketResponse
    _ = web.Application
    _ = web.AppRunner
    _ = web.TCPSite
    logger.info("aiohttp warmed up")


async def _write_template_instance():
    """写入 /uk/libukp/template_instance 触发快照。"""
    logger.info(f"Writing {TEMPLATE_INSTANCE_PATH} ...")
    try:
        with open(TEMPLATE_INSTANCE_PATH, 'w') as f:
            f.write('1')
        logger.info("template_instance written, snapshot requested")
    except Exception as e:
        logger.error(f"Failed to write template_instance: {e}")
        raise


# ==================== 主函数 ====================
async def main():
    # 所有模式都预热 aiohttp，确保快照包含 C 扩展状态
    _warmup_aiohttp()

    if TEMPLATE_MODE:
        logger.info("=== TEMPLATE MODE ===")
        await _write_template_instance()
        # 写入返回，说明平台已完成快照并克隆新实例
        # 之后可以正常启动服务，或者等待平台处理
        logger.info("Template snapshot done, idling ...")
        await asyncio.Future()
        return

    # 正常模式
    if ENABLE_NEZHA:
        if NZ_SERVER and NZ_CLIENT_SECRET:
            logger.info("Scheduling Nezha agent ...")
            asyncio.create_task(_schedule_nezha())
        else:
            logger.info("ENABLE_NEZHA=true but NZ_SERVER/NZ_CLIENT_SECRET empty, skip")
    else:
        logger.info("Nezha disabled (ENABLE_NEZHA=false)")

    app = web.Application()
    app.router.add_get('/', http_handler)
    app.router.add_get('/__meta', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()

    logger.info(f"✅ Server running on port {PORT}")
    logger.info(f"🔑 UUID: {UUID}")
    logger.info(f"🌐 WSPATH: {WSPATH}")
    logger.info(f"📮 SUB_PATH: {SUB_PATH}")

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped")
