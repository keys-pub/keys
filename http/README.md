# HTTP

This package extends the net/http package to provide signed requests using a keys.EdX25519Key.

```go
key := keys.GenerateEdX25519Key()

// Vault POST
content := []byte(`[{"data":"dGVzdGluZzE="},{"data":"dGVzdGluZzI="}]`)
contentHash := http.ContentHash(content)
req, err := http.NewAuthRequest("POST", "https://keys.pub/vault/"+key.ID().String(), bytes.NewReader(content), contentHash, time.Now(), key)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("curl -H \"Authorization: %s\" -d %q %q\n", req.Header["Authorization"][0], string(content), req.URL.String())

// Vault GET
req, err = http.NewAuthRequest("GET", "https://keys.pub/vault/"+key.ID().String(), nil, "", time.Now(), key)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("curl -H \"Authorization: %s\" %q\n", req.Header["Authorization"][0], req.URL.String())
```
