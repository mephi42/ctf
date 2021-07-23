import atheris

with atheris.instrument_imports():
    import io
    import sys
    import zipfile
    import zlib
    import _lzma
    import tempfile
    import shutil
    import subprocess
    import string

    import turbozipfile


@atheris.instrument_func
def TestOneInput(data):
    try:
        tmp1 = tempfile.mkdtemp()
        tmp2 = tempfile.mkdtemp()
        rmtree = True
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if False:
                    for info in z.infolist():
                        for c in info.filename:
                            if c not in string.printable:
                                return
                z.extractall(tmp1)
            with turbozipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(tmp2)
            rmtree = False
            subprocess.check_call(["diff", "-u", "-r", tmp1, tmp2])
            rmtree = True
        finally:
            if rmtree:
                shutil.rmtree(tmp1)
                shutil.rmtree(tmp2)
    except (
        zipfile.BadZipFile,
        turbozipfile.BadZipFile,
        IndexError,
        ValueError,
        NotImplementedError,
        OverflowError,
        KeyError,
        zlib.error,
        EOFError,
        OSError,
        RuntimeError,
        _lzma.LZMAError,
    ):
        pass
    except:
        print(sys.exc_info())
        raise


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
