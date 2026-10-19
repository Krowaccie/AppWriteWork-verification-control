FROM mcr.microsoft.com/playwright/mcp@sha256:690763cbb437ee7233f538a953bb5390bf03791eb5c965b471e59d17a6132fcb
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools && rm -rf /var/lib/apt/lists/*
USER 1000:1000
ENV HOME=/home/node
ENV NODE_PATH=/app/node_modules
ENTRYPOINT ["node", "/verifier/verification/controller/portable/product-browser.cjs"]
