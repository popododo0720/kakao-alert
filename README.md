# kakao-alert

Alertmanager webhook → KakaoTalk "send to me" (나에게 보내기). Python standard library only.

| Endpoint | | Expose |
|---|---|---|
| `POST /alertmanager` | Alertmanager webhook receiver: one short Korean message per notification | cluster-internal only |
| `POST /test` | Sends a test message | cluster-internal only |
| `GET /login`, `GET /callback` | One-time Kakao login and consent (`talk_message`) | LAN/VPN through the gateway |
| `GET /metrics`, `GET /healthz` | Prometheus metrics, liveness | cluster-internal |

Tokens:
- The access token lives 6–12 h; the refresh token lives 2 months.
- When less than a month is left, a refresh returns a new refresh token and invalidates the old one.
- Every token response is therefore written to a Kubernetes Secret (`stringData` merge patch through the pod's service account) before it is used.
- A background loop refreshes at least daily and before the access token expires, so the refresh token keeps rotating even when no alert fires.
- Only one Kakao account can own the bridge: `KAKAO_ALLOWED_USER_ID`, or else the first account that logged in.

Messages use the Kakao text template (200 characters) with a link button. The link's domain must be registered in the Kakao app (Platform → Web → site domain).

## Configuration

| Variable | Default | |
|---|---|---|
| `KAKAO_REST_API_KEY` / `_FILE` | — | App REST API key (client_id) |
| `KAKAO_CLIENT_SECRET` / `_FILE` | — | Client secret, if enabled in the app |
| `KAKAO_REDIRECT_URI` | — | Must match the app's Redirect URI, e.g. `https://kakao.home.arpa/callback` |
| `KAKAO_ALLOWED_USER_ID` | — | Optional Kakao member number allowed to log in |
| `LINK_URL` | `https://alertmanager.home.arpa` | Button link |
| `TOKEN_SECRET_NAME` | `kakao-alert-tokens` | Secret in the pod's namespace (needs get + patch) |
| `PORT` | `8080` | |

Metrics:
- `kakao_alert_messages_total{result}`
- `kakao_alert_token_refresh_total{result}`
- `kakao_alert_logged_in`
- `kakao_alert_access_expires_timestamp_seconds`
- `kakao_alert_refresh_expires_timestamp_seconds`

## Image

`ghcr.io/popododo0720/kakao-alert`, built by `.github/workflows/image.yaml`: `vX.Y.Z` tags → `X.Y.Z`, `X.Y`; main → `main`, `sha-<short>`.

## Development

```
python -m unittest discover -s tests -v
```
