# IntentShield with its dev extra (tests), no ML extras, so reviewers need not build anything themselves.
#   docker build -t intentshield .
#   docker run --rm intentshield                                    # verify the demo proxy end to end
#   docker run --rm intentshield pytest -q                          # the test suite
#   echo '<hook event JSON>' | docker run --rm -i intentshield intentshield-hook claude
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --extra dev --frozen
ENV PATH="/app/.venv/bin:$PATH" INTENTSHIELD_INTENT_MODEL_DIR=/nonexistent
CMD ["intentshield-mcp-verify", "--config", "configs/mcp-proxy.demo.json", "--stdio"]
