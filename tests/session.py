#!/usr/bin/env python3
"""Holds a Guacamole session open over the HTTP tunnel, as a browser would.

    session.py GUAC_URL TOKEN ID [TYPE]

TYPE is "c" for a connection (the default) or "g" for a connection group.

Prints "open" once the tunnel is connected and "closed" when it ends, from
either side. Ends the session cleanly on SIGTERM or SIGINT.
"""

import codecs
import os
import signal
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

url, token, connection = sys.argv[1:4]
kind = sys.argv[4] if len(sys.argv) > 4 else "c"
tunnel = url + "/tunnel"

data = urllib.parse.urlencode({
    "token": token, "GUAC_DATA_SOURCE": os.environ.get("PAM_DATA_SOURCE", "postgresql"), "GUAC_ID": connection, "GUAC_TYPE": kind,
    "GUAC_WIDTH": "800", "GUAC_HEIGHT": "600", "GUAC_DPI": "96",
}).encode()

try:
    with urllib.request.urlopen(urllib.request.Request(tunnel + "?connect", data), timeout=15) as response:
        uuid = response.read().decode().strip()
        headers = {}
        if response.headers.get("Guacamole-Tunnel-Token"):
            headers["Guacamole-Tunnel-Token"] = response.headers["Guacamole-Tunnel-Token"]
except urllib.error.HTTPError as e:
    print("refused", e.code, e.headers.get("Guacamole-Error-Message", ""), flush=True)
    sys.exit(1)

print("open", flush=True)
done = threading.Event()


def write(instructions):
    request = urllib.request.Request(tunnel + "?write:" + uuid, instructions.encode(), dict(headers))
    request.add_header("Content-Type", "application/octet-stream")
    try:
        urllib.request.urlopen(request, timeout=10).read()
    except Exception:
        done.set()


def instructions(buffer):
    """Splits off the complete instructions at the start of buffer, each as
    its list of elements, returning them with what remains. Elements are
    prefixed by their length in characters, so may hold "," or ";"."""
    found = []
    while True:
        elements, i = [], 0
        while True:
            dot = buffer.find(".", i)
            if dot < 0:
                return found, buffer
            end = dot + 1 + int(buffer[i:dot])
            if end >= len(buffer):
                return found, buffer
            elements.append(buffer[dot + 1:end])
            i = end + 1
            if buffer[end] == ";":
                break
        found.append(elements)
        buffer = buffer[i:]


def read():
    """Reads instructions as they arrive, answering each "sync" at once, as
    a browser does. Guacamole streams one read response for as long as no
    other read takes over, so it is read in pieces rather than whole."""
    n = 0
    while not done.is_set():
        request = urllib.request.Request("%s?read:%s:%d" % (tunnel, uuid, n), headers=dict(headers))
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.headers.get("Guacamole-Status-Code"):
                    break
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                buffer, received = "", False
                while not done.is_set():
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    received = True
                    found, buffer = instructions(buffer + decoder.decode(chunk))
                    for opcode, *args in found:
                        if opcode == "sync":
                            write("4.sync,%d.%s;" % (len(args[0]), args[0]))
                        elif opcode in ("disconnect", "error"):
                            done.set()
        except Exception:
            break
        if not received:
            break
        n += 1
    done.set()


def stop(*_):
    write("10.disconnect;")
    done.set()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
threading.Thread(target=read, daemon=True).start()

# guacd drops users it has not heard from for 15 seconds
while not done.wait(3):
    write("3.nop;")

print("closed", flush=True)
