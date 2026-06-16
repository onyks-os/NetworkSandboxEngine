# Stage 1: Build the Svelte Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
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

# Install dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy and install python package
COPY backend/ /app/backend/
RUN pip install -e /app/backend/

# Copy built frontend assets into location where FastAPI will serve them
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Expose dev port
EXPOSE 8000

# To run, docker requires --privileged or --cap-add=NET_ADMIN to access network namespaces
ENTRYPOINT ["python", "-m", "nse.cli", "serve", "--dev", "--host", "0.0.0.0"]
