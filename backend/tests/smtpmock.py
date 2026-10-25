"""Минимальный SMTP-сервер для испытаний: принимает письма в память и умеет имитировать временные и постоянные ошибки."""
from __future__ import annotations

import asyncio
import base64
from email import message_from_bytes, policy


class FakeSMTP:
    def __init__(self, user: str = "", password: str = ""):
        self.messages: list[dict] = []
        self.mode = "ok"                 # ok | tempfail (451 на MAIL) | permfail (550 на всех получателей) | drop (обрыв после приветствия) | slow
        self.reject: set[str] = set()    # адреса, которые сервер отклоняет (550)
        self.user, self.password = user, password
        self.connections = 0
        self._writers: list[asyncio.StreamWriter] = []
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            for w in self._writers:
                w.close()
            await asyncio.wait_for(self.server.wait_closed(), 5)

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.append(w)
        send = lambda line: (w.write((line + "\r\n").encode()), None)[1]  # noqa: E731
        send("220 fake ESMTP")
        if self.mode == "drop":
            w.close()
            return
        mail_from, rcpts, authed = "", [], not self.user
        try:
            while True:
                line = (await r.readline()).decode(errors="replace").rstrip("\r\n")
                if not line:
                    break
                cmd = line.upper()
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    send("250-fake"); send("250-AUTH PLAIN LOGIN"); send("250 8BITMIME")
                elif cmd.startswith("AUTH PLAIN"):
                    parts = base64.b64decode(line.split(" ", 2)[2]).split(b"\0")
                    if parts[-2:] == [self.user.encode(), self.password.encode()]:
                        authed = True
                        send("235 2.7.0 ok")
                    else:
                        send("535 5.7.8 Authentication credentials invalid")
                elif cmd.startswith("MAIL FROM"):
                    if not authed:
                        send("530 5.7.0 Authentication required")
                    elif self.mode == "tempfail":
                        send("451 4.3.0 Try again later")
                    else:
                        mail_from, rcpts = line.split(":", 1)[1].strip(" <>"), []
                        send("250 ok")
                elif cmd.startswith("RCPT TO"):
                    addr = line.split(":", 1)[1].strip(" <>").lower()
                    if self.mode == "permfail" or addr in self.reject:
                        send("550 5.1.1 User unknown")
                    else:
                        rcpts.append(addr)
                        send("250 ok")
                elif cmd == "DATA":
                    if not rcpts:
                        send("554 5.5.1 no valid recipients")
                        continue
                    send("354 go")
                    data = b""
                    while not data.endswith(b"\r\n.\r\n"):
                        data += await r.readline()
                    msg = message_from_bytes(data[:-5], policy=policy.default)
                    self.messages.append({"from": mail_from, "rcpts": rcpts, "msg": msg, "raw": data})
                    send("250 2.0.0 queued")
                elif cmd == "NOOP":
                    send("250 ok")
                elif cmd == "QUIT":
                    send("221 bye")
                    break
                else:
                    send("502 not implemented")
                await w.drain()
            await w.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            w.close()
