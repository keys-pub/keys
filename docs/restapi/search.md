# REST API (Search)

## GET /search

Search.

| Request | Description              |
| ------- | ------------------------ |
| q       | Query.                   |
| limit   | Limit number of results. |

```shell
curl https://api.keys.app/search?q=gabriel
```

```json
{
  "results": [
    {
      "kid": "GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm",
      "user": {
        "kid": "GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm",
        "name": "gabriel",
        "seq": 2,
        "service": "github",
        "url": "https://gist.github.com/gabriel/d12f5ca05f5d0fc9899f4a3c2276118e",
        "ucts": "2019-10-30T17:31:02.096Z"
      }
    }
  ]
}
```

| Response | Description               |
| -------- | ------------------------- |
| results  | Array&lt;SearchResult&gt; |

SearchResult.

| Response | Description                   |
| -------- | ----------------------------- |
| kid      | Key identifier.               |
| user     | [User](../user.md), optional. |

User.

| JSON      | Description                     |
| --------- | ------------------------------- |
| `kid`     | Key identifier.                 |
| `name`    | Username.                       |
| `seq`     | Sigchain seq (position).        |
| `service` | Service name (github, twitter). |
| `url`     | URL to signed statement.        |
| `ucts`    | URL check timestamp.            |
