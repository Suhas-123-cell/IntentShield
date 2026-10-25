import uvicorn

from .logs import configure_logging


def main() -> None:
    configure_logging()
    # No proxy headers: every local client would be a trusted proxy and could pick its own
    # address in X-Forwarded-For, dodging the rate limit.
    uvicorn.run("intentshield.api:app", host="127.0.0.1", port=8000, reload=False, proxy_headers=False)


if __name__ == "__main__":
    main()
