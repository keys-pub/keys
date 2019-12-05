# REST API (Errors)

The API returns errors in the format:

```json
{
  "error": {
    "message": "user public key not found",
    "code": 404
  }
}
```

| Code | Description                                      |
| ---- | ------------------------------------------------ |
| 400  | Bad request.                                     |
| 401  | Unauthenticated.                                 |
| 403  | Forbidden.                                       |
| 404  | Resource not found.                              |
| 409  | Resource already exists.                         |
| 413  | Entity too large, if request body was too large. |
| 429  | Too many requests, if you hit a request limit.   |
