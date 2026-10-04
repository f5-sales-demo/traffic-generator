"""Patch pinned native wrk to stop new requests and drain dispatched requests at deadline."""

from pathlib import Path


def replace_once(source: str, before: str, after: str) -> str:
    """Fail closed when the pinned native source no longer matches the adapter."""
    if source.count(before) != 1:
        message = "pinned wrk drain adapter anchor mismatch"
        raise ValueError(message)
    return source.replace(before, after)


def adapt(root: Path) -> None:
    """Keep all native workers, Lua payloads and full measurement duration intact."""
    header = root / "src/wrk.h"
    header.write_text(
        replace_once(
            header.read_text(),
            "    uint64_t bytes;",
            "    uint64_t bytes;\n    uint64_t drain_started;",
        )
    )
    path = root / "src/wrk.c"
    source = path.read_text()
    source = replace_once(
        source,
        "    if (stop) aeStop(loop);",
        """    if (stop) {
        uint64_t now = time_us();
        if (!thread->drain_started) thread->drain_started = now;
        bool pending = false;
        for (uint64_t i = 0; i < thread->connections; i++) {
            if (thread->cs[i].pending) pending = true;
        }
        if (!pending) aeStop(loop);
        else if (now - thread->drain_started > cfg.timeout * 1000) {
            thread->errors.timeout++;
            aeStop(loop);
        }
    }""",
    )
    source = replace_once(
        source,
        "    aeDeleteEventLoop(loop);\n    zfree(thread->cs);",
        """    for (uint64_t i = 0; i < thread->connections; i++) {
        connection *c = &thread->cs[i];
        if (c->fd >= 0) {
            sock.close(c);
            close(c->fd);
        }
    }
    aeDeleteEventLoop(loop);
    zfree(thread->cs);""",
    )
    source = replace_once(
        source,
        "    return connect_socket(thread, c);",
        """    if (stop) {
        c->pending = 0;
        c->fd = -1;
        return -1;
    }
    return connect_socket(thread, c);""",
    )
    source = replace_once(
        source,
        "        c->delayed = cfg.delay;\n        aeCreateFileEvent(thread->loop, c->fd, AE_WRITABLE, socket_writeable, c);",
        """        if (stop) {
            aeDeleteFileEvent(thread->loop, c->fd, AE_WRITABLE | AE_READABLE);
            c->written = 0;
            goto done;
        }
        c->delayed = cfg.delay;
        aeCreateFileEvent(thread->loop, c->fd, AE_WRITABLE, socket_writeable, c);""",
    )
    source = replace_once(
        source,
        "    if (c->delayed) {",
        """    if (stop && !c->pending) {
        aeDeleteFileEvent(loop, fd, AE_WRITABLE | AE_READABLE);
        sock.close(c);
        close(c->fd);
        c->fd = -1;
        return;
    }
    if (c->delayed) {""",
    )
    source = replace_once(
        source,
        "        c->thread->bytes += n;",
        """        c->thread->bytes += n;
        if (stop && !c->pending) return;""",
    )
    path.write_text(source)
