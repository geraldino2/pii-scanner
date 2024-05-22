import unicodedata
import base64
import json
import re


def normalizeString(text):
    # type: (str) -> str
    """Receives a raw string, normalizes unicoded chars and returns ascii"""
    text = text.encode("utf-8", "ignore").decode("utf-8")
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return str(text)


def findJwts(text):
    # type: (str) -> Set[str]
    """Find JWTs in a text, returns a set of their payloads"""
    jwtSet = set()
    jwtRegex = re.compile(r"([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.([a-zA-Z0-9_-]+)?)")
    for jwtMatch in jwtRegex.findall(text):
        for matchGroup in jwtMatch:
            print(matchGroup)
            jwtSet.add(matchGroup)
    payloadSet = set()
    for token in jwtSet:
        try:
            jwtParts = token.split(".")
            if len(jwtParts) > 1:
                payload = jwtParts[1]
                payloadPadding = "=" * (4 - len(payload) % 4)
                payload += payloadPadding
                decoded = base64.urlsafe_b64decode(payload)
                json_payload = json.loads(decoded)
                payloadSet.add(normalizeString(json_payload))
        except:
            continue
    return payloadSet


def findBase64Words(text):
    # type: (str) -> Set[str]
    """Find base64 words in a text, returns a decoded set of them"""
    base64Set = set()
    base64Regex = re.compile(
        r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )
    for base64Match in base64Regex.findall(text):
        print(base64Match)
        try:
            base64Set.add(base64.urlsafe_b64decode(base64Match))
        except:
            continue
    return base64Set
