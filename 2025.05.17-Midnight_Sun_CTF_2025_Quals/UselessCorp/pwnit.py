from requests import Session

def main():
    url = "https://useless-94tszh4z.ctf.pro"
    s = Session()
    r = s.post(url, data={
        "name": "a",
        "email": "b",
        "subject": "c",
        "message": "d'",
    })
    r.raise_for_status()
    print(r.content.decode())


if __name__ == "__main__":
    main()
