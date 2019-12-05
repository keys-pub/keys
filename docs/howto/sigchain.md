# Sigchain

## `keys sigchain show`

View a sigchain.

```shell
keys sigchain show -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

Outputs sigchain.

```txt
{".sig":"cBkbRkMERy0yo436kRuWNF/O4E2OcVnbw9uy2o/D1Gc9+hXpIHkasnusqkknUyV+l9QMKVRbbLe121Ws5jeSBQ==","data":"4xsu+g26GIHBobmLN+kKEFOuYIBA3eY1FrGLDI9WEFc=","kid":"QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st","seq":1,"type":"bpk"}
{".sig":"PiSMFgz2SiH+2hcb60uza6GLWHtmx6bK+hNVF8uFvSbkweFCAdPUc8WUbSfVo3fL7Msbf69kqwjjj2Rv98CxAA==","data":"eyJraWQiOiJRQnJiekNXSzVNZjVmenpGYXlDcVY0Zm5aYUdVVE1SanZBeHlFcWYzODhzdCIsIm5hbWUiOiJnYWJyaWVsIiwic2VxIjoyLCJzZXJ2aWNlIjoiZ2l0aHViIiwidXJsIjoiaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FicmllbC8wMWNlNDNhYTg2N2FhM2IwMTA1YTZkMThiZTdjOThmNiJ9","kid":"QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st","prev":"w8O6TeLPbNPfYGJhv6xiEE4952hwNMYOoDP4bP3EWOQ=","seq":2,"type":"user"}
```

## `keys sigchain statement add`

Add to sigchain. Anything added to a sigchain is public.

```shell
echo "test" | keys sigchain statement add -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

## `keys sigchain statement revoke`

Revoke statement.

```shell
keys sigchain statement revoke -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st -seq 2
```
