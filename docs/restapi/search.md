# REST API (Search)

## GET /search

Search.

| Request | Description              |
| ------- | ------------------------ |
| q       | Query.                   |
| limit   | Limit number of results. |

```shell
curl https://keys.pub/search?q=gabriel
```

```json
// TODO: Output
```

| Response | Description               |
| -------- | ------------------------- |
| results  | Array&lt;SearchResult&gt; |

SearchResult.

| Response | Description     |
| -------- | --------------- |
| kid      | Key identifier. |
| users    | []UserResult    |

UserResult.

| JSON     | Description              |
| -------- | ------------------------ |
| `err`    | Error.                   |
| `status` | Status.                  |
| `ts`     | Timestamp.               |
| `user`   | User.                    |
| `vts`    | Last verified timestamp. |
