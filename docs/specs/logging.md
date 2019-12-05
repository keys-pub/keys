# Logging

Logging for any package can be configured via that packages [SetLogger](https://godoc.org/github.com/keys-pub/keys#SetLogger).

For example, using logrus, and setting it on the keys and keyring package.

```go
logger := logrus.StandardLogger()
formatter := &logrus.TextFormatter{
    FullTimestamp:   true,
    TimestampFormat: time.RFC3339Nano,
}
logger.SetFormatter(formatter)
logger.SetLevel(logrus.DebugLevel)

keys.SetLogger(logger)
keyring.SetLogger(logger)
```

Some packages require context with logging, such as the firestore and httpserver packages.
