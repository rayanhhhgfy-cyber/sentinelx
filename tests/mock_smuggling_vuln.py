"""Mock smuggling-vulnerable server for testing.

Simulates a CL.TE desync: when a request contains BOTH Content-Length and
Transfer-Encoding, the 'backend' waits ~6s (desync timeout) before responding.
A normal request responds immediately.
"""

import asyncio


async def handle(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(8192), timeout=5)
        text = data.decode("utf-8", "replace")
        has_cl = "content-length:" in text.lower()
        has_te = "transfer-encoding:" in text.lower()
        if has_cl and has_te:
            await asyncio.sleep(6)  # desync: backend waits for chunked body
            body = b"desync-timeout-simulated"
        else:
            body = b"ok"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body)
        writer.write(resp)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 5061)
    print("mock-vuln-smuggling on 127.0.0.1:5061")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
