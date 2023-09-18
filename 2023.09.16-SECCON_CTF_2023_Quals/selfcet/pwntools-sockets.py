ORIG_PROCESS = pwnlib.tubes.process.process.__init__


class P2CWrite:
    def __init__(self, fp):
        self.fp = fp
        self.closed = False

    def close(self):
        self.fp.close()
        self.closed = True

    def write(self, data):
        self.fp.send(data)

    def flush(self):
        pass


class C2PRead:
    def __init__(self, fp):
        self.fp = fp
        self.closed = False

    def close(self):
        self.fp.close()
        self.closed = True

    def fileno(self):
        return self.fp.fileno()

    def read(self, numb=-1):
        return self.fp.recv(numb)


def process_init(self, *args, **kwargs):
    p2cwrite = kwargs.pop("p2cwrite")
    c2pread = kwargs.pop("c2pread")
    ORIG_PROCESS(self, *args, **kwargs)
    self.proc.stdin = P2CWrite(p2cwrite)
    self.proc.stdout = C2PRead(c2pread)


pwnlib.tubes.process.process.__init__ = process_init

# parent, child = socket.socketpair()
# tube.process(stdin=child, p2cwrite=parent, stdout=child, c2pread=child, stderr=child)
