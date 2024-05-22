# Package Index
Typing with Jython is odly defined and no index generator seems to cover it. Types are defined in a comment below each function, as close as it can be to what should be supported by mypy.

* [main](#main)
  * [BurpExtender](#main.BurpExtender)
    * [\_\_init\_\_](#main.BurpExtender.__init__)
    * [defineMetadata](#main.BurpExtender.defineMetadata)
    * [registerListeners](#main.BurpExtender.registerListeners)
    * [registerExtenderCallbacks](#main.BurpExtender.registerExtenderCallbacks)
    * [defineUI](#main.BurpExtender.defineUI)
    * [getTabCaption](#main.BurpExtender.getTabCaption)
    * [getUiComponent](#main.BurpExtender.getUiComponent)
    * [processHttpMessage](#main.BurpExtender.processHttpMessage)
    * [processProxyMessage](#main.BurpExtender.processProxyMessage)
    * [extensionUnloaded](#main.BurpExtender.extensionUnloaded)
* [core](#core)
  * [core.test\_piiscanner](#core.test_piiscanner)
  * [core.cpfscanner](#core.cpfscanner)
    * [CPFScanner](#core.cpfscanner.CPFScanner)
      * [\_\_init\_\_](#core.cpfscanner.CPFScanner.__init__)
      * [isValidCpf](#core.cpfscanner.CPFScanner.isValidCpf)
      * [find](#core.cpfscanner.CPFScanner.find)
  * [core.textutils](#core.textutils)
    * [normalizeString](#core.textutils.normalizeString)
    * [findCpfJwts](#core.textutils.findCpfJwts)
    * [findCpfBase64Words](#core.textutils.findCpfBase64Words)
  * [core.parser](#core.parser)
    * [Parser](#core.parser.Parser)
      * [\_\_init\_\_](#core.parser.Parser.__init__)
      * [parseCookies](#core.parser.Parser.parseCookies)
      * [parseParameters](#core.parser.Parser.parseParameters)
      * [parseRequestMessageInfo](#core.parser.Parser.parseRequestMessageInfo)
      * [parseResponseMessageInfo](#core.parser.Parser.parseResponseMessageInfo)
  * [core.piiscanner](#core.piiscanner)
    * [PIIScanner](#core.piiscanner.PIIScanner)
      * [\_\_init\_\_](#core.piiscanner.PIIScanner.__init__)
      * [createIssue](#core.piiscanner.PIIScanner.createIssue)
      * [treatRequest](#core.piiscanner.PIIScanner.treatRequest)
      * [treatResponse](#core.piiscanner.PIIScanner.treatResponse)

<a id="main"></a>

# main

<a id="main.BurpExtender"></a>

## BurpExtender Objects

```python
class BurpExtender(IBurpExtender, IHttpListener, IProxyListener,
                   IExtensionStateListener, ITab)
```

<a id="main.BurpExtender.__init__"></a>

#### \_\_init\_\_

```python
def __init__()
```

Defines config

<a id="main.BurpExtender.defineMetadata"></a>

#### defineMetadata

```python
def defineMetadata()
```

Defines metadata used by Burp (extension name)

<a id="main.BurpExtender.registerListeners"></a>

#### registerListeners

```python
def registerListeners()
```

Registers itself as a listener for IHttpListener, IProxyListener,
IExtensionStateListener

<a id="main.BurpExtender.registerExtenderCallbacks"></a>

#### registerExtenderCallbacks

```python
def registerExtenderCallbacks(callbacks)
```

Defined in IBurpExtenderCallbacks, invoked on load.
- Stores the callbacks object, an instance of IExtensionHelpers and
a stdout writer
- Registers itself as a listener for specific Burp defined events
- Defines metadata
- Defines UI

<a id="main.BurpExtender.defineUI"></a>

#### defineUI

```python
def defineUI()
```

Defines the UI for the extension tab. UI consists basically of a
JList containing items from the consumer variable _issues.

<a id="main.BurpExtender.getTabCaption"></a>

#### getTabCaption

```python
def getTabCaption()
```

Defined in ITab. Defines tab caption.

<a id="main.BurpExtender.getUiComponent"></a>

#### getUiComponent

```python
def getUiComponent()
```

Defined in ITab. Defines the main UI component for the tab.

<a id="main.BurpExtender.processHttpMessage"></a>

#### processHttpMessage

```python
def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
```

Defined in IHttpListener, invoked with HTTP traffic outside proxy.
Process traffic from general HTTP listener, parses the message if it is
a response and forwards it to a consumer.

<a id="main.BurpExtender.processProxyMessage"></a>

#### processProxyMessage

```python
def processProxyMessage(messageIsRequest, message)
```

Defined in IProxyListener, invoked with proxy traffic.
Process traffic from proxy, parses the message and forwards it to a
consumer.

<a id="main.BurpExtender.extensionUnloaded"></a>

#### extensionUnloaded

```python
def extensionUnloaded()
```

Defined in IExtensionStateListener, invoked on unload.
Graceful exit.

<a id="core"></a>

# core

<a id="core.test_piiscanner"></a>

# core.test\_piiscanner

<a id="core.cpfscanner"></a>

# core.cpfscanner

<a id="core.cpfscanner.CPFScanner"></a>

## CPFScanner Objects

```python
class CPFScanner()
```

<a id="core.cpfscanner.CPFScanner.__init__"></a>

#### \_\_init\_\_

```python
def __init__(regexLookaheadCheckbox)
```

Defines metadata

<a id="core.cpfscanner.CPFScanner.isValidCpf"></a>

#### isValidCpf

```python
def isValidCpf(cpfCandidate)
```

Check if the CPF candidate is actually a valid CPF

<a id="core.cpfscanner.CPFScanner.find"></a>

#### find

```python
def find(text)
```

Find CPF candidates using an aggressive regexp that allows
overlapping and inconsistent separators, validates them and returns
a list of matches

<a id="core.textutils"></a>

# core.textutils

<a id="core.textutils.normalizeString"></a>

#### normalizeString

```python
def normalizeString(text)
```

Receives a raw string, normalizes unicoded chars and returns ascii

<a id="core.textutils.findCpfJwts"></a>

#### findCpfJwts

```python
def findCpfJwts(text)
```

Find JWTs in a text, returns a set of their payloads

<a id="core.textutils.findCpfBase64Words"></a>

#### findCpfBase64Words

```python
def findCpfBase64Words(text)
```

Find base64 words in a text, returns a decoded set of them

<a id="core.parser"></a>

# core.parser

<a id="core.parser.Parser"></a>

## Parser Objects

```python
class Parser()
```

<a id="core.parser.Parser.__init__"></a>

#### \_\_init\_\_

```python
def __init__(helpers, callbacks)
```

Defines internal config

<a id="core.parser.Parser.parseCookies"></a>

#### parseCookies

```python
def parseCookies(rawCookieArr)
```

Converts an array of cookies into a dict mapping names to values

<a id="core.parser.Parser.parseParameters"></a>

#### parseParameters

```python
def parseParameters(rawParametersArr)
```

Converts an array of params into a dict mapping names to values

<a id="core.parser.Parser.parseRequestMessageInfo"></a>

#### parseRequestMessageInfo

```python
def parseRequestMessageInfo(messageInfo,
                            toolFlag=IBurpExtenderCallbacks.TOOL_PROXY)
```

Parses a messageInfo object into multiple text fields

<a id="core.parser.Parser.parseResponseMessageInfo"></a>

#### parseResponseMessageInfo

```python
def parseResponseMessageInfo(messageInfo,
                             toolFlag=IBurpExtenderCallbacks.TOOL_PROXY)
```

Parses a messageInfo object into multiple text fields

<a id="core.piiscanner"></a>

# core.piiscanner

<a id="core.piiscanner.PIIScanner"></a>

## PIIScanner Objects

```python
class PIIScanner()
```

<a id="core.piiscanner.PIIScanner.__init__"></a>

#### \_\_init\_\_

```python
def __init__(regexLookaheadCheckbox, regexJwtCheckbox, regexBase64Checkbox)
```

Defines metadata, list of issues presented to the UI, matchers

<a id="core.piiscanner.PIIScanner.createIssue"></a>

#### createIssue

```python
def createIssue(matcherType, pii, url)
```

Creates an issue in the UI if it is a new one

<a id="core.piiscanner.PIIScanner.treatRequest"></a>

#### treatRequest

```python
def treatRequest(*args, **kwargs)
```

Invoked when any response is intercepted by Burp, but useless here

<a id="core.piiscanner.PIIScanner.treatResponse"></a>

#### treatResponse

```python
def treatResponse(source="",
                  method="",
                  url="",
                  status="",
                  body="",
                  cookies=dict(),
                  headers=list())
```

Invoked when any response is intercepted by Burp. Finds PII using the
matchers defined in self.MATCHERS and creates an issue for each of
them.

