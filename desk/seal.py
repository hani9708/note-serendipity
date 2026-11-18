"""오늘의 문장 위젯 데이터를 암호화해 data.json으로 쓴다.

평문 JSON은 저장소에 올리지 않는다. 열쇠는 환경 변수 STUDIO_DESK_KEY
(32바이트, base64url)로만 받는다. 열쇠는 노션 임베드 주소의 # 뒤에만 있다.

사용:
  python3 seal.py plain.json            # data.json 생성
  python3 seal.py --new-key             # 새 열쇠 출력 (처음 한 번만)
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main() -> None:
    if sys.argv[1:] == ["--new-key"]:
        print(b64(AESGCM.generate_key(bit_length=256)))
        return
    key = unb64(os.environ["STUDIO_DESK_KEY"])
    plain = json.load(open(sys.argv[1], encoding="utf-8"))
    raw = json.dumps(plain, ensure_ascii=False).encode()
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, raw, None)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"v": 1, "iv": b64(iv), "ct": b64(ct)}, f)
        f.write("\n")


if __name__ == "__main__":
    main()
