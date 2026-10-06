# Sandbox for MSB's MCP servers. The attacks really write files and run commands,
# so every server runs in here; benchmarks/msb.py stays on the host and reaches
# them over `docker exec -i` stdio.
#   docker build -f benchmarks/msb.Dockerfile -t intentshield-msb artifacts/data/MSB
#   docker run -d --name intentshield-msb intentshield-msb
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv

COPY . /msb
WORKDIR /msb/data/tools/attack_tools
RUN uv sync

WORKDIR /msb
# MSB's setup.py rewrites these placeholders in place; do the same for /msb.
RUN sed -i 's#/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME#/msb/operation_space/output/file_name.txt#g; s#/ABSOLUTE/PATH/TO/SPACE/INFORMATION/PERSONAL#/msb/operation_space/information/personal_information.json#g' data/attack_task.jsonl \
    && sed -i 's#/ABSOLUTE/PATH/TO/SPACE/INFORMATION#/msb/operation_space/information#g' data/agent_task.jsonl \
    && mkdir -p operation_space/output
# Warm npm's cache so each case does not download its servers again.
RUN for p in @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-sequential-thinking \
        @modelcontextprotocol/server-memory time-mcp metmuseum-mcp; do npm cache add "$p"; done

CMD ["sleep", "infinity"]
