from javax.swing import DefaultListModel

class PIIScanner:
    def __init__(self):
        self._issues = DefaultListModel()
        self.EXT_NAME = "PII Scanner"

    def treatResponse(self, body, source, cookies, headers):
        with open("results.txt","w") as f:
            f.write(body.encode('ascii', 'ignore')+"\n")
            f.write(source+"\n")
            for cookie in cookies:
               f.write(cookie+":")
               for value in cookies[cookie]:
                   f.write(value+",")
               f.write("\n")
            for header in headers:
                self._issues.addElement(header)
                f.write(header+"\n")
