"""
Manual verification harness for the CRLF-injection false-positive fix.

Not wired into a pytest suite (repo has none yet) - run directly from the
`backend/` directory (matching how uvicorn actually launches the app,
WORKDIR /app -> app.main:app, so `app` is the top-level package there too):
    cd backend && python3 -m app.test_crlf_check_manual

Spins up two tiny raw-socket TCP servers on localhost:

  1. FALSE-POSITIVE server (port 8901): mimics exactly what verilyme.com
     (Vercel) and shop.whoop.com (Cloudflare) actually did - it takes the
     injected query value and echoes it verbatim INSIDE the Location
     header's URL value on a 302 redirect. The payload appears somewhere
     in the raw response, but never as an independent header line. The
     v2 check must return None here.

  2. TRUE-POSITIVE server (port 8902): a deliberately vulnerable server
     that writes the raw, unsanitized query value directly into the
     header block, so a %0d%0a in the input really does create a second,
     independent "Set-Cookie: swas_crlf_probe=1" header line. The v2
     check must still catch this.

Both servers also serve a plain baseline response (no injected param) so
the check's baseline-diff step has something realistic to diff against.
"""
import asyncio
import urllib.parse

from . import detective


async def _false_positive_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    data = await reader.read(4096)
    request_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
    path = request_line.split(" ")[1]
    parsed = urllib.parse.urlparse(path)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    q_raw = parsed.query  # keep raw (undecoded) so %0d%0a stays literal text

    # Simulate Vercel/Cloudflare: the raw query string gets embedded, still
    # percent-encoded (never actually decoded into real CR/LF bytes), inside
    # the Location URL of a redirect. This is the exact false-positive shape
    # observed on verilyme.com and shop.whoop.com.
    location = f"/landed?echo={q_raw}"
    body = b"redirecting..."
    resp = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: {location}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
    ).encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()
    _ = qs


async def _true_positive_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    data = await reader.read(4096)
    request_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
    path = request_line.split(" ")[1]
    parsed = urllib.parse.urlparse(path)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    raw_value = qs.get("q", [""])[0]

    # Deliberately vulnerable: decode %0d%0a into REAL CRLF bytes and splice
    # it straight into the header block unsanitized, so it becomes a genuine
    # second header line - real response splitting.
    decoded = urllib.parse.unquote(raw_value)
    body = b"ok"
    resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"X-Echo: {decoded}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
    ).encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()


async def main():
    fp_server = await asyncio.start_server(_false_positive_handler, "127.0.0.1", 8901)
    tp_server = await asyncio.start_server(_true_positive_handler, "127.0.0.1", 8902)
    async with fp_server, tp_server:
        asyncio.ensure_future(fp_server.serve_forever())
        asyncio.ensure_future(tp_server.serve_forever())
        await asyncio.sleep(0.2)  # let servers bind

        fp_result = await detective.check_crlf_injection("http://127.0.0.1:8901/?q=1")
        tp_result = await detective.check_crlf_injection("http://127.0.0.1:8902/?q=1")

        print("FALSE-POSITIVE-SHAPED target result:", fp_result)
        print("TRUE-POSITIVE-SHAPED target result:  ", tp_result)

        assert fp_result is None, "REGRESSION: false-positive pattern was flagged again!"
        assert tp_result is not None and tp_result["vuln_type"] == "crlf_injection", (
            "REGRESSION: real response splitting was missed!"
        )
        print("\nPASS: false positive suppressed, true positive still caught.")


if __name__ == "__main__":
    asyncio.run(main())
