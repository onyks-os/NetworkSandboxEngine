# Stage 1: Build the Svelte Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/gui/gui_svelte
COPY gui/gui_svelte/package*.json ./
RUN npm install
COPY gui/gui_svelte/ ./
RUN npm run build

# Stage 2: Create Python Backend & System runtime
FROM python:3.11-slim

# Install kernel network utilities required by the engine
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    conntrack \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy python package configuration
COPY pyproject.toml README.md ./
COPY nse/ /app/nse/
COPY gui/ /app/gui/

# Install the Python package with cli/gui extras
RUN pip install --no-cache-dir .[cli,gui]

# Copy built frontend assets into location where FastAPI will serve them
COPY --from=frontend-builder /app/gui/gui_svelte/dist /app/gui/gui_svelte/dist

# Expose dev port
EXPOSE 8000

# To run, docker requires --privileged or --cap-add=NET_ADMIN to access network namespaces
# We run the FastAPI daemon (gui.server)
ENTRYPOINT ["python", "-m", "gui.server", "serve", "--dev", "--host", "0.0.0.0"]
