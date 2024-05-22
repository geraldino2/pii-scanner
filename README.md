# PII Scanner

PII Scanner is a Burp Suite extension that parses all responses received and looks for PII (currently, [CPFs](https://pt.wikipedia.org/wiki/Cadastro_de_Pessoas_F%C3%ADsicas)).
- From every source (proxy, repeater, intruder, extender);
- Anywhere in the response (body, headers);
- Identifies and decodes encoded fields (Base64, JWT) in responses (optional: impacts perfomance);
- Supports RegExp lookaheads (optional: impacts perfomance).

## PoC
Check [usage/README.md](usage/README.md) for usage instructions.
- [Valid CPF](http://i.geraldino2.com/dr?status=200&body=12345678909)
- [Valid CPF using RegExp lookahead](http://i.geraldino2.com/dr?status=200&body=000000000000012345678909)
- [Base64 CPF](http://i.geraldino2.com/dr?status=200&body=MTIzNDU2Nzg5MDkK)
- [JWT CPF](http://i.geraldino2.com/dr?status=200&body=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MTYzNDQyNjQsImV4cCI6MTc0Nzg4MDI2NCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXSwiQ1BGIjoiMTIzLjQ1Ni43ODktMDkifQ.HqZt_Oa3bjdHkoBCPshaBitF6a6WaXFWn2JevRbVSy8)

## Structure
The defined code structure is pretty simple. `main.py` implements `BurpExtender`, deals with all that is needed to setup the extension and uses a consumer to deal with the requests and control the UI.

`piiscanner.py` defines `PIIScanner`, the consumer and parses requests using auxiliary modules (`parser.py`, `textutils.py`). `PIIScanner` is easily extensible as PIIs are identified using matchers. `CPFScanner` is the only implemented matcher, and works by a combination of a RegExp and digits checksum.

Additional documentation is available [here](docs.md).

![image](https://github.com/geraldino2/pii-scanner/assets/70358808/c478f163-a0e0-4a49-9cbe-3f038e7f5fad)

## Testing
Testing is quite complex as extensions use Jython (Python 2) and dependencies from both Java and Burp are required, but is possible and some unit tests were createad using `unittest`. As `unittest` doesn't have mock in Python2, it should be installed from `pip`, through Jython.
```
$ java -jar $JYTHON_JAR_PATH -m ensurepip # install pip
$ java -jar $JYTHON_JAR_PATH -m pip install mock # install Mock for unittest
$ java -cp $JYTHON_JAR_PATH:$BURP_JAR_PATH org.python.util.jython -m unittest discover -s . -v
```

### TODO
- Filter responses by Content-Type;
- More tests;
- More matchers;
- Improve logging.
