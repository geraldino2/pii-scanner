## TODO
- README
- Unit tests
- Logging
- Docs

### Testing
Testing is quite complex as extensions use Jython (Python 2) and dependencies from both Java and Burp are required, but is possible and some unit tests were createad using `unittest`. As `unittest` doesn't have mock in Python2, it should be installed from `pip`, through Jython.
```
$ java -jar $JYTHON_JAR_PATH -m ensurepip # install pip
$ java -jar $JYTHON_JAR_PATH -m pip install mock # install Mock for unittest
$ java -cp $JYTHON_JAR_PATH:$BURP_JAR_PATH org.python.util.jython -m unittest discover -s . -v
```