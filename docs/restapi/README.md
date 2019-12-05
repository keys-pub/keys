# REST API

The API endpoint is [api.keys.app](https://api.keys.app/search).

- [Search](search.md)
- [Sigchain](sigchain.md)
- [Errors](errors.md)

| Resource                                                | Method | Description                                                                                                          |
| ------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------- |
| [/search](search#get-search)                            | GET    | Search.                                                                                                              |
| [/sigchain/:kid](sigchain.md#get-sigchain-kid)          | GET    | Get a sigchain.                                                                                                      |
| [/sigchain/:kid/:seq](sigchain.md#put-sigchain-kid-seq) | PUT    | Put a sigchain entry. Must be a valid signed sigchain statement by the key. If it exists already, returns 409 error. |
| [/sigchains](sigchain.md#get-sigchains)                 | GET    | Get all sigchains.                                                                                                   |
