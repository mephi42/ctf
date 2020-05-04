from flask import *
from base64 import b64decode, b64encode
from string import printable
from random import choice
from lxml import etree
import os

app = Flask(__name__, static_folder=&#34;static&#34;, static_url_path=&#34;/static&#34;)
app.secret_key = &#34;gLTAqe12Z3OufWG7&#34;
filename = &#34;/admin_pass&#34; #os.getenv(&#34;FILENAME&#34;)

@app.route(&#34;/admin&#34;)
def admin():
    try:
        if request.values.get(&#34;cookies&#34;):
            session[&#34;cookies&#34;] = int(request.values.get(&#34;cookies&#34;))
            return (&#39;&#39;, 200)
        root = etree.fromstring(b64decode(session[&#34;lxml&#34;]).decode())
        is_admin = bool(int(root.xpath(&#34;data/is_admin&#34;)[0].text))
        if not is_admin:
            return &#34;You are not an admin!&#34;
    except Exception as e:
        return &#34;Error: &#34; + str(e)
    with open(filename, &#34;r&#34;) as file:
        password = file.read()
    if request.values.get(&#34;password&#34;) == password:
        return send_file(&#34;flag.png&#34;)
    return redirect(url_for(&#34;/site&#34;))

@app.route(&#34;/site&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def site():
    try:
        if request.values.get(&#34;cookies&#34;):
            session[&#34;cookies&#34;] = int(request.values.get(&#34;cookies&#34;))
            return (&#39;&#39;, 200)
        root = etree.fromstring(b64decode(session[&#34;lxml&#34;]).decode())
        cookies = session[&#34;cookies&#34;]
        username = str(root.xpath(&#34;data/username&#34;)[0].text)
        is_admin = bool(int(root.xpath(&#34;data/is_admin&#34;)[0].text))
        return render_template(&#34;site.html&#34;, username=username, is_admin=is_admin, cookies=cookies, filename=filename)
    except Exception as e:
        return &#34;Error: &#34; + str(e)

@app.route(&#34;/login&#34;, methods = [&#39;POST&#39;])
def login():
    username = request.values.get(&#34;username&#34;)
    version = request.values.get(&#34;version&#34;)
    session[&#34;lxml&#34;] = b64encode(f&#34;&#34;&#34;!<p>