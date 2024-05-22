from javax.swing import DefaultListModel
from textutils import findCpfBase64Words, findCpfJwts, normalizeString
from cpfscanner import CPFScanner
from threading import Lock


class PIIScanner:
    def __init__(self, regexLookaheadCheckbox, regexJwtCheckbox, regexBase64Checkbox):
        # type: (IBurpExtenderCallbacks, IExtensionHelpers, JCheckBox, JCheckBox, JCheckBox) -> None
        """Defines metadata, list of issues presented to the UI, matchers"""
        self.issues = set()
        self._issues = DefaultListModel()
        self.EXT_NAME = "PII Scanner"
        self.MATCHERS = [CPFScanner(regexLookaheadCheckbox)]
        self._regexJwtCheckbox = regexJwtCheckbox
        self._regexBase64Checkbox = regexBase64Checkbox
        self._lock = Lock()

    def createIssue(self, matcherType, pii, url):
        # type: (str, str, str) -> None
        """Creates an issue in the UI if it is a new one"""
        with self._lock:
            issue = "[{}] {} (at {})".format(matcherType, pii, url)
            if issue not in self.issues:
                self.issues.add(issue)
                self._issues.addElement(issue)

    def treatRequest(self, *args, **kwargs):
        # type: (Optional[str], Optional[str]) -> None
        """Invoked when any response is intercepted by Burp, but useless here"""
        pass

    def treatResponse(
        self,
        source="",
        method="",
        url="",
        status="",
        body="",
        cookies=dict(),
        headers=list(),
    ):
        # type: (str, str, str, int, str, Dict[str, Set[str]], List[str]) -> None
        """
        Invoked when any response is intercepted by Burp. Finds PII using the
        matchers defined in self.MATCHERS and creates an issue for each of
        them.
        """
        cookiesStr = " ".join(
            cookie_value
            for cookie in cookies
            for cookie_value in map(str, cookies[cookie])
        )
        headersStr = " ".join(headers)
        text = normalizeString(body + " " + cookiesStr + " " + headersStr)
        if self._regexJwtCheckbox.isSelected():
            text += " " + " ".join(findCpfJwts(text))
        if self._regexBase64Checkbox.isSelected():
            text += " " + " ".join(findCpfBase64Words(text))
        for matcher in self.MATCHERS:
            for pii in matcher.find(text):
                self.createIssue(matcher.type, pii, url)
