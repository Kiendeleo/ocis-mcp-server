# Stage 1: Build
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/ocis-mcp-server ./cmd/ocis-mcp-server

# Stage 2: Runtime
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates tzdata \
	&& addgroup -S mcp && adduser -S mcp -G mcp \
	&& mkdir -p /var/lib/ocis-mcp \
	&& chown mcp:mcp /var/lib/ocis-mcp

COPY --from=builder /bin/ocis-mcp-server /usr/local/bin/ocis-mcp-server

USER mcp
VOLUME ["/var/lib/ocis-mcp"]

EXPOSE 8090

# OAuth mode stores encrypted grants here; override with OCIS_MCP_GRANT_DB.
ENV OCIS_MCP_GRANT_DB=/var/lib/ocis-mcp/grants.db

ENTRYPOINT ["ocis-mcp-server"]
