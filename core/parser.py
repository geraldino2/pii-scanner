from burp import IBurpExtenderCallbacks
from collections import defaultdict, namedtuple


class Parser:
    def __init__(self, helpers, callbacks):
        """Defines internal config"""
        self._helpers = helpers
        self._callbacks = callbacks

    def parseCookies(self, rawCookieArr):
        # type: (List[ICookie]) -> Dict[str, Set[str]]
        """Converts an array of cookies into a dict mapping names to values"""
        cookies = defaultdict(set)
        for rawCookie in rawCookieArr:
            cookies[rawCookie.getName()].add(rawCookie.getValue())
        return dict(cookies)

    def parseParameters(self, rawParametersArr):
        # type: (List[IParameter]) -> Dict[str, Set[str]]
        """Converts an array of params into a dict mapping names to values"""
        params = defaultdict(set)
        for rawParameter in rawParametersArr:
            params[rawParameter.getName()].add(rawParameter.getValue())
        return dict(params)

    def parseRequestMessageInfo(
        self, messageInfo, toolFlag=IBurpExtenderCallbacks.TOOL_PROXY
    ):
        # type: (IHttpRequestResponse, int) -> Tuple[str, str, str, Dict[str, Set[str], List[str], str]
        """Parses a messageInfo object into multiple text fields"""
        requestInfo = self._helpers.analyzeRequest(messageInfo)

        source = self._callbacks.getToolName(toolFlag)
        method = requestInfo.getMethod()
        url = str(requestInfo.getUrl())  # getUrl returns a java.net.URL object
        parameters = self.parseParameters(requestInfo.getParameters())
        headers = requestInfo.getHeaders()
        body = messageInfo.getRequest()[requestInfo.getBodyOffset() :]
        RequestData = namedtuple(
            "RequestData", ["source", "method", "url", "parameters", "headers", "body"]
        )
        return RequestData(source, method, url, parameters, headers, body)

    def parseResponseMessageInfo(
        self, messageInfo, toolFlag=IBurpExtenderCallbacks.TOOL_PROXY
    ):
        # type: (IHttpRequestResponse, int) -> Tuple[str, str, str, int, str, Dict[str, Set[str]], List[str]]
        """Parses a messageInfo object into multiple text fields"""
        httpResponse = messageInfo.getResponse()
        parsedResponse = self._helpers.analyzeResponse(httpResponse)

        requestInfo = self.parseRequestMessageInfo(messageInfo)
        method = requestInfo.method
        url = requestInfo.url

        source = self._callbacks.getToolName(toolFlag)
        status = parsedResponse.getStatusCode()
        bodyOffset = parsedResponse.getBodyOffset()
        body = self._helpers.bytesToString(httpResponse[bodyOffset:])
        cookies = self.parseCookies(parsedResponse.getCookies())
        headers = parsedResponse.getHeaders()
        ResponseData = namedtuple(
            "ResponseData",
            ["source", "method", "url", "status", "body", "cookies", "headers"],
        )
        return ResponseData(source, method, url, status, body, cookies, headers)
