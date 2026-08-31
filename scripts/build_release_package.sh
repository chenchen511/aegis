#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
RELEASE_ROOT="${RELEASE_ROOT:-${ROOT_DIR}/release}"
RELEASE_DIR="${RELEASE_ROOT}/${VERSION}"
ZIP_NAME="aegis-${VERSION}-linux-amd64-release.zip"
ZIP_PATH="${RELEASE_ROOT}/${ZIP_NAME}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
EBPF_BUILDER_IMAGE="${EBPF_BUILDER_IMAGE:-aegis-agent-builder-ubi8:5.8.0}"
AGENT_ARTIFACT_IMAGE="${AGENT_ARTIFACT_IMAGE:-aegis-agent-artifacts:release}"
BUILDER_SERVICE_IMAGE="${BUILDER_SERVICE_IMAGE:-aegis-system/builder:latest}"
USE_LOCAL_IMAGES="${USE_LOCAL_IMAGES:-0}"
LOCAL_API_SERVER_IMAGE="${LOCAL_API_SERVER_IMAGE:-aegis-api-server:latest}"
LOCAL_SERVER_IMAGE="${LOCAL_SERVER_IMAGE:-aegis-server:latest}"
LOCAL_DC_IMAGE="${LOCAL_DC_IMAGE:-aegis-dc:latest}"
LOCAL_FRONTEND_IMAGE="${LOCAL_FRONTEND_IMAGE:-aegis-frontend:latest}"
LOCAL_MCP_GATEWAY_IMAGE="${LOCAL_MCP_GATEWAY_IMAGE:-aegis-mcp-gateway:latest}"
MCP_GATEWAY_SERVICE_IMAGE="${MCP_GATEWAY_SERVICE_IMAGE:-aegis-system/mcp-gateway:latest}"
COMBINED_IMAGE_ARCHIVE="${COMBINED_IMAGE_ARCHIVE:-0}"

info() {
  printf '[release] %s\n' "$*"
}

die() {
  printf '[release] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

validate_version() {
  if [ -z "${VERSION}" ]; then
    die "version argument is required (for example: v6.2)"
  fi

  case "${VERSION}" in
    [A-Za-z0-9]*)
      case "${VERSION}" in
        *[!A-Za-z0-9._-]*) die "version contains unsupported characters: ${VERSION}" ;;
      esac
      ;;
    *)
      die "version must start with a letter or number: ${VERSION}"
      ;;
  esac
}

confirm_replace_zip() {
  if [ ! -f "${ZIP_PATH}" ]; then
    return
  fi

  if [ "${FORCE:-0}" = "1" ]; then
    rm -f "${ZIP_PATH}"
    return
  fi

  if [ ! -t 0 ]; then
    die "${ZIP_PATH} already exists; remove it manually or run from an interactive shell"
  fi

  read -r -p "${ZIP_PATH} already exists. Replace it? [y/N] " answer
  case "${answer}" in
    y|Y|yes|YES) rm -f "${ZIP_PATH}" ;;
    *) die "aborted by user" ;;
  esac
}

confirm_replace_release_dir() {
  if [ ! -d "${RELEASE_DIR}" ] || ! find "${RELEASE_DIR}" -mindepth 1 -print -quit | grep -q .; then
    return
  fi

  if [ "${FORCE:-0}" = "1" ]; then
    rm -rf "${RELEASE_DIR}"
    return
  fi

  if [ ! -t 0 ]; then
    die "${RELEASE_DIR} already exists; set FORCE=1 to replace it or remove it manually"
  fi

  read -r -p "${RELEASE_DIR} already exists. Replace it? [y/N] " answer
  case "${answer}" in
    y|Y|yes|YES) rm -rf "${RELEASE_DIR}" ;;
    *) die "aborted by user" ;;
  esac
}

prepare_release_dir() {
  confirm_replace_release_dir
  mkdir -p \
    "${RELEASE_DIR}/images" \
    "${RELEASE_DIR}/build-context/bpf" \
    "${RELEASE_DIR}/backend/scripts" \
    "${RELEASE_DIR}/backend/migrations"
}

extract_agent_artifact() {
  local agent_container
  agent_container="$(docker create "${AGENT_ARTIFACT_IMAGE}")"
  if ! docker cp \
      "${agent_container}:/out/aegis-agent-linux-amd64" \
      "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64" ||
    ! docker cp \
      "${agent_container}:/out/aegis-agent.tar.gz" \
      "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64.tar.gz" ||
    ! docker cp \
      "${agent_container}:/out/bpf/." \
      "${RELEASE_DIR}/build-context/bpf/"; then
    docker rm -f "${agent_container}" >/dev/null 2>&1 || true
    die "failed to extract Linux AMD64 agent artifacts from ${AGENT_ARTIFACT_IMAGE}"
  fi
  docker rm "${agent_container}" >/dev/null

  test -s "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64" || die "missing Linux AMD64 agent binary"
  test -s "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64.tar.gz" || die "missing Linux AMD64 agent archive"
  compgen -G "${RELEASE_DIR}/build-context/bpf/*.bpf.o" >/dev/null || die "missing eBPF objects from agent image"
}

build_agent_artifact() {
  info "building shared eBPF builder image (${EBPF_BUILDER_IMAGE})"
  docker build --platform "${DOCKER_PLATFORM}" \
    -f "${ROOT_DIR}/docker/ebpf-builder-base/Dockerfile" \
    -t "${EBPF_BUILDER_IMAGE}" \
    "${ROOT_DIR}"

  info "building Linux AMD64 agent artifacts inside ${EBPF_BUILDER_IMAGE}"
  docker build --platform "${DOCKER_PLATFORM}" \
    -f "${ROOT_DIR}/agent/Dockerfile" \
    --build-arg "EBPF_BASE_IMAGE=${EBPF_BUILDER_IMAGE}" \
    -t "${AGENT_ARTIFACT_IMAGE}" \
    "${ROOT_DIR}/agent"

  extract_agent_artifact
}

build_builder_service_image() {
  info "building builder service inside ${EBPF_BUILDER_IMAGE}"
  docker build --platform "${DOCKER_PLATFORM}" \
    -f "${ROOT_DIR}/builder/Dockerfile" \
    --build-arg "EBPF_BASE_IMAGE=${EBPF_BUILDER_IMAGE}" \
    -t "${BUILDER_SERVICE_IMAGE}" \
    "${ROOT_DIR}"
}

write_minio_context() {
  cat > "${RELEASE_DIR}/build-context/minio-entrypoint.sh" <<'EOF'
#!/bin/sh
set -eu

"$@" &
minio_pid="$!"

cleanup() {
  kill "${minio_pid}" 2>/dev/null || true
  wait "${minio_pid}" 2>/dev/null || true
}
trap cleanup INT TERM

until mc alias set myminio http://127.0.0.1:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  sleep 2
done

mc mb myminio/aegis-templates --ignore-existing >/dev/null 2>&1 || true
mc mb myminio/agent-artifacts --ignore-existing >/dev/null 2>&1 || true
mc mb myminio/generated-scripts --ignore-existing >/dev/null 2>&1 || true
mc mb myminio/aegis-builds --ignore-existing >/dev/null 2>&1 || true
mc mb myminio/aegis-releases --ignore-existing >/dev/null 2>&1 || true
mc anonymous set download myminio/agent-artifacts >/dev/null 2>&1 || true
mc anonymous set download myminio/aegis-releases >/dev/null 2>&1 || true

if [ -f /agent-artifacts/aegis-agent-linux-amd64.tar.gz ]; then
  mc cp /agent-artifacts/aegis-agent-linux-amd64.tar.gz myminio/agent-artifacts/aegis-agent.tar.gz >/dev/null
fi

wait "${minio_pid}"
EOF
  chmod +x "${RELEASE_DIR}/build-context/minio-entrypoint.sh"

  cat > "${RELEASE_DIR}/Dockerfile.minio" <<'EOF'
FROM minio/mc:latest AS mc
FROM minio/minio:latest
COPY --from=mc /usr/bin/mc /usr/bin/mc
COPY build-context/aegis-agent-linux-amd64.tar.gz /agent-artifacts/
COPY build-context/minio-entrypoint.sh /usr/bin/minio-entrypoint.sh
RUN chmod +x /usr/bin/minio-entrypoint.sh
ENTRYPOINT ["/usr/bin/minio-entrypoint.sh"]
CMD ["minio", "server", "/data", "--console-address", ":9001"]
EOF
}

write_init_sql() {
  {
    printf '%s\n' '-- Generated release database init script.'
    printf '%s\n' '-- Source files are concatenated from migrations/*.sql in lexical order.'
    find "${ROOT_DIR}/migrations" -maxdepth 1 -type f -name '*.sql' | LC_ALL=C sort | while read -r migration; do
      printf '\n-- ============================================================\n'
      printf -- '-- Source: %s\n' "$(basename "${migration}")"
      printf -- '-- ============================================================\n'
      cat "${migration}"
      printf '\n'
    done
  } > "${RELEASE_DIR}/backend/scripts/init.sql"
  # PostgreSQL runs the init script as its unprivileged postgres user. The
  # release process may run with umask 0077, so explicitly make the bind mount
  # readable rather than relying on the caller's umask.
  chmod 0644 "${RELEASE_DIR}/backend/scripts/init.sql"
}

copy_release_migration() {
  local migration

  for migration in \
    029_v6.2_agent_guard.sql \
    030_v6.2_zcode_agent_guard_profile.sql \
    031_v6.2_agent_escape_permission_first.sql \
    032_v6.3_agent_session_awareness.sql \
    033_v6.3_mcp_platform_control_plane.sql \
    034_v6.3_mcp_platform_audit_analysis.sql \
    035_v6.3_mcp_client_endpoints.sql \
    036_v6.3_mcp_security_rules.sql \
    037_v6.4_agent_skill_security.sql \
    038_v6.4_agent_skill_scan_snapshots.sql; do
    test -s "${ROOT_DIR}/migrations/${migration}" || die "missing required release migration: ${ROOT_DIR}/migrations/${migration}"
    cp "${ROOT_DIR}/migrations/${migration}" "${RELEASE_DIR}/backend/migrations/${migration}"
    chmod 0644 "${RELEASE_DIR}/backend/migrations/${migration}"
  done
}

write_release_compose() {
  cat > "${RELEASE_DIR}/docker-compose.yml" <<'EOF'
version: "3.8"

services:
  postgres:
    image: pgvector/pgvector:pg16
    container_name: aegis-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: aegis_db
      POSTGRES_USER: aegis_user
      POSTGRES_PASSWORD: ${DB_PASSWORD:-a_strong_db_password}
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=C"
    command:
      - "postgres"
      - "-c"
      - "max_connections=100"
      - "-c"
      - "shared_buffers=256MB"
      - "-c"
      - "effective_cache_size=768MB"
      - "-c"
      - "maintenance_work_mem=128MB"
      - "-c"
      - "checkpoint_completion_target=0.9"
      - "-c"
      - "wal_buffers=16MB"
      - "-c"
      - "default_statistics_target=100"
      - "-c"
      - "random_page_cost=1.1"
      - "-c"
      - "effective_io_concurrency=200"
      - "-c"
      - "work_mem=4MB"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backend/scripts/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro
    ports:
      - "${DB_PORT:-5432}:5432"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis_user -d aegis_db"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  db-migrate:
    image: pgvector/pgvector:pg16
    restart: "no"
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      PGPASSWORD: ${DB_PASSWORD:-a_strong_db_password}
    volumes:
      - ./backend/migrations/029_v6.2_agent_guard.sql:/migrations/029_v6.2_agent_guard.sql:ro
      - ./backend/migrations/030_v6.2_zcode_agent_guard_profile.sql:/migrations/030_v6.2_zcode_agent_guard_profile.sql:ro
      - ./backend/migrations/031_v6.2_agent_escape_permission_first.sql:/migrations/031_v6.2_agent_escape_permission_first.sql:ro
      - ./backend/migrations/032_v6.3_agent_session_awareness.sql:/migrations/032_v6.3_agent_session_awareness.sql:ro
      - ./backend/migrations/033_v6.3_mcp_platform_control_plane.sql:/migrations/033_v6.3_mcp_platform_control_plane.sql:ro
      - ./backend/migrations/034_v6.3_mcp_platform_audit_analysis.sql:/migrations/034_v6.3_mcp_platform_audit_analysis.sql:ro
      - ./backend/migrations/035_v6.3_mcp_client_endpoints.sql:/migrations/035_v6.3_mcp_client_endpoints.sql:ro
      - ./backend/migrations/036_v6.3_mcp_security_rules.sql:/migrations/036_v6.3_mcp_security_rules.sql:ro
      - ./backend/migrations/037_v6.4_agent_skill_security.sql:/migrations/037_v6.4_agent_skill_security.sql:ro
      - ./backend/migrations/038_v6.4_agent_skill_scan_snapshots.sql:/migrations/038_v6.4_agent_skill_scan_snapshots.sql:ro
    command:
      - "psql"
      - "-v"
      - "ON_ERROR_STOP=1"
      - "-h"
      - "postgres"
      - "-U"
      - "aegis_user"
      - "-d"
      - "aegis_db"
      - "-f"
      - "/migrations/029_v6.2_agent_guard.sql"
      - "-f"
      - "/migrations/030_v6.2_zcode_agent_guard_profile.sql"
      - "-f"
      - "/migrations/031_v6.2_agent_escape_permission_first.sql"
      - "-f"
      - "/migrations/032_v6.3_agent_session_awareness.sql"
      - "-f"
      - "/migrations/033_v6.3_mcp_platform_control_plane.sql"
      - "-f"
      - "/migrations/034_v6.3_mcp_platform_audit_analysis.sql"
      - "-f"
      - "/migrations/035_v6.3_mcp_client_endpoints.sql"
      - "-f"
      - "/migrations/036_v6.3_mcp_security_rules.sql"
      - "-f"
      - "/migrations/037_v6.4_agent_skill_security.sql"
      - "-f"
      - "/migrations/038_v6.4_agent_skill_scan_snapshots.sql"
    networks:
      - aegis-network

  redis:
    image: redis:7-alpine
    container_name: aegis-redis
    restart: unless-stopped
    command:
      - "redis-server"
      - "--requirepass"
      - "${REDIS_PASSWORD:-a_strong_redis_password}"
      - "--maxmemory"
      - "256mb"
      - "--maxmemory-policy"
      - "allkeys-lru"
      - "--appendonly"
      - "yes"
      - "--appendfsync"
      - "everysec"
    volumes:
      - redis_data:/data
    ports:
      - "${REDIS_PORT:-6379}:6379"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD:-a_strong_redis_password}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  minio:
    image: aegis-system/minio-with-agent:latest
    container_name: aegis-minio
    restart: unless-stopped
    environment:
      MINIO_ROOT_USER: ${MINIO_ACCESS_KEY:-minio_admin}
      MINIO_ROOT_PASSWORD: ${MINIO_SECRET_KEY:-a_third_strong_secret_password}
    volumes:
      - minio_data:/data
    ports:
      - "${MINIO_API_PORT:-9000}:9000"
      - "${MINIO_CONSOLE_PORT:-9001}:9001"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "mc alias set health http://127.0.0.1:9000 \"$${MINIO_ROOT_USER}\" \"$${MINIO_ROOT_PASSWORD}\" >/dev/null 2>&1 && mc ready health"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 20s

  builder:
    image: aegis-system/builder:latest
    container_name: aegis-builder
    restart: unless-stopped
    depends_on:
      minio:
        condition: service_healthy
    environment:
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY:-minio_admin}
      MINIO_SECRET_KEY: ${MINIO_SECRET_KEY:-a_third_strong_secret_password}
      BUILDER_KEY_FILE: /data/builder.key
    volumes:
      - builder_data:/data
    ports:
      - "19096:19096"
    networks:
      - aegis-network

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: aegis-zookeeper
    restart: unless-stopped
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "echo ruok | nc localhost 2181 || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    container_name: aegis-kafka
    restart: unless-stopped
    depends_on:
      zookeeper:
        condition: service_started
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    ports:
      - "29092:9092"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD", "kafka-topics", "--bootstrap-server", "localhost:9092", "--list"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 30s

  server:
    image: aegis-system/server:latest
    container_name: aegis-server
    restart: unless-stopped
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 223.5.5.5
    dns_search:
      - .
    depends_on:
      postgres:
        condition: service_healthy
      db-migrate:
        condition: service_completed_successfully
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    environment:
      DATABASE_HOST: postgres
      DATABASE_PORT: 5432
      DATABASE_USER: aegis_user
      DATABASE_PASSWORD: ${DB_PASSWORD:-a_strong_db_password}
      DATABASE_DBNAME: aegis_db
      DATABASE_SSLMODE: disable
      DATABASE_MAX_OPEN_CONNS: 25
      DATABASE_MAX_IDLE_CONNS: 10
      DATABASE_CONN_MAX_LIFETIME: 300
      REDIS_HOST: redis
      REDIS_PORT: 6379
      REDIS_PASSWORD: ${REDIS_PASSWORD:-a_strong_redis_password}
      REDIS_DB: 0
      REDIS_POOL_SIZE: 20
      MINIO_ARTIFACT_BASE_URL: "http://${EXTERNAL_IP:-localhost}:9000/aegis-releases"
      KAFKA_BROKERS: kafka:9092
      KAFKA_GROUP_ID: aegis-server-consumer
      SERVER_GRPC_PORT: 19090
      SERVER_EXTERNAL_IP: ${EXTERNAL_IP:-}
      SERVER_EXTERNAL_GRPC_PORT: 19090
      AGENT_AUTH_TOKEN: ${AGENT_TOKEN:-a_very_secret_agent_token}
      AGENT_HEARTBEAT_TIMEOUT: 90
      AGENT_SCRIPT_TIMEOUT: 300
      AGENT_GUARD_ACTION_CONSUMER_ENABLED: ${AGENT_GUARD_ACTION_CONSUMER_ENABLED:-false}
    ports:
      - "19090:19090"
      - "19094:19094"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 19090 || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s

  api-server:
    image: aegis-system/api-server:latest
    container_name: aegis-api-server
    restart: unless-stopped
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 223.5.5.5
    dns_search:
      - .
    depends_on:
      postgres:
        condition: service_healthy
      db-migrate:
        condition: service_completed_successfully
      redis:
        condition: service_healthy
      minio:
        condition: service_healthy
      builder:
        condition: service_started
      server:
        condition: service_healthy
      kafka:
        condition: service_healthy
    environment:
      DATABASE_HOST: postgres
      DATABASE_PORT: 5432
      DATABASE_USER: aegis_user
      DATABASE_PASSWORD: ${DB_PASSWORD:-a_strong_db_password}
      DATABASE_DBNAME: aegis_db
      DATABASE_SSLMODE: disable
      DATABASE_MAX_OPEN_CONNS: 25
      DATABASE_MAX_IDLE_CONNS: 10
      DATABASE_CONN_MAX_LIFETIME: 300
      REDIS_HOST: redis
      REDIS_PORT: 6379
      REDIS_PASSWORD: ${REDIS_PASSWORD:-a_strong_redis_password}
      REDIS_DB: 0
      REDIS_POOL_SIZE: 20
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY:-minio_admin}
      MINIO_SECRET_KEY: ${MINIO_SECRET_KEY:-a_third_strong_secret_password}
      MINIO_USE_SSL: "false"
      MINIO_ARTIFACT_BASE_URL: "http://${EXTERNAL_IP:-localhost}:9000/aegis-releases"
      SERVER_HTTP_PORT: 8082
      SERVER_GRPC_PORT: 19093
      AGENT_HUB_PORT: 19090
      SERVER_EXTERNAL_IP: ${EXTERNAL_IP:-}
      GRPC_SERVER_ADDRESS: server:19094
      BUILDER_GRPC_ADDRESS: builder:19096
      AGENT_AUTH_TOKEN: ${AGENT_TOKEN:-a_very_secret_agent_token}
      KAFKA_BROKERS: kafka:9092
      KAFKA_GROUP_ID: aegis-api-server-consumer
      LLM_API_KEY: ${LLM_API_KEY:-}
      LLM_BASE_URL: ${LLM_BASE_URL:-https://api.openai.com/v1}
      LLM_MODEL_NAME: ${LLM_MODEL_NAME:-gpt-4}
      AGENT_GUARD_ENABLED: ${AGENT_GUARD_ENABLED:-false}
      AGENT_GUARD_POLICY_WRITE_ENABLED: ${AGENT_GUARD_POLICY_WRITE_ENABLED:-false}
      AGENT_GUARD_ANALYSIS_ENABLED: ${AGENT_GUARD_ANALYSIS_ENABLED:-false}
      AGENT_GUARD_ACTION_ENABLED: ${AGENT_GUARD_ACTION_ENABLED:-false}
      AGENT_GUARD_TOOL_ADAPTER_ENABLED: ${AGENT_GUARD_TOOL_ADAPTER_ENABLED:-false}
      AGENT_GUARD_SCOPE_SIGNING_KEY: ${AGENT_GUARD_SCOPE_SIGNING_KEY:-}
      MCP_GATEWAY_BASE_URL: ${MCP_GATEWAY_BASE_URL:-http://mcp-gateway:8084}
      MCP_GATEWAY_PUBLIC_BASE_URL: ${MCP_GATEWAY_PUBLIC_BASE_URL:-http://localhost:8084}
      MCP_GATEWAY_RUNTIME_BASE_URL: ${MCP_GATEWAY_RUNTIME_BASE_URL:-http://api-server:8082}
      MCP_GATEWAY_RUNTIME_SECRET: ${MCP_GATEWAY_RUNTIME_SECRET:-change-me-mcp-gateway-runtime}
      MCP_GATEWAY_SNAPSHOT_FILE: ${MCP_GATEWAY_SNAPSHOT_FILE:-}
      MCP_GATEWAY_SIGNING_KEY: ${MCP_GATEWAY_SIGNING_KEY:-}
      MCP_CATALOG_SIGNING_KEY: ${MCP_CATALOG_SIGNING_KEY:-}
      MCP_ASSISTANT_ENABLED: ${MCP_ASSISTANT_ENABLED:-false}
      MCP_ASSISTANT_CLIENT_KEY: ${MCP_ASSISTANT_CLIENT_KEY:-}
      MCP_ASSISTANT_CLIENT_TOKEN: ${MCP_ASSISTANT_CLIENT_TOKEN:-}
    ports:
      - "8082:8082"
      - "19093:19093"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8082/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s

  mcp-gateway:
    image: aegis-system/mcp-gateway:latest
    container_name: aegis-mcp-gateway
    restart: unless-stopped
    depends_on:
      api-server:
        condition: service_healthy
    environment:
      MCP_GATEWAY_PORT: 8084
      MCP_GATEWAY_SNAPSHOT_FILE: ${MCP_GATEWAY_SNAPSHOT_FILE:-}
      MCP_GATEWAY_SIGNING_KEY: ${MCP_GATEWAY_SIGNING_KEY:-}
      MCP_GATEWAY_RUNTIME_BASE_URL: ${MCP_GATEWAY_RUNTIME_BASE_URL:-http://api-server:8082}
      MCP_GATEWAY_RUNTIME_SECRET: ${MCP_GATEWAY_RUNTIME_SECRET:-change-me-mcp-gateway-runtime}
    ports:
      - "8084:8084"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD", "/mcp-gateway", "--healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

  dc:
    image: aegis-system/dc:latest
    container_name: aegis-dc
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      db-migrate:
        condition: service_completed_successfully
      kafka:
        condition: service_healthy
    environment:
      DATABASE_HOST: postgres
      DATABASE_PORT: 5432
      DATABASE_USER: aegis_user
      DATABASE_PASSWORD: ${DB_PASSWORD:-a_strong_db_password}
      DATABASE_DBNAME: aegis_db
      DATABASE_SSLMODE: disable
      DATABASE_MAX_OPEN_CONNS: 25
      DATABASE_MAX_IDLE_CONNS: 5
      DATABASE_CONN_MAX_LIFETIME: 300
      KAFKA_BROKERS: kafka:9092
      KAFKA_GROUP_ID: aegis-dc-consumer
      KAFKA_TOPIC: aegis.security.events
      GRPC_SERVER_PORT: 19092
      LLM_API_KEY: ${LLM_API_KEY:-}
      LLM_BASE_URL: ${LLM_BASE_URL:-https://api.openai.com/v1}
      LLM_MODEL_NAME: ${LLM_MODEL_NAME:-gpt-4}
      AGENT_GUARD_PROJECTION_ENABLED: ${AGENT_GUARD_PROJECTION_ENABLED:-false}
      AGENT_BEHAVIOR_RULES_ENABLED: ${AGENT_BEHAVIOR_RULES_ENABLED:-false}
      AGENT_BEHAVIOR_FINDINGS_ENABLED: ${AGENT_BEHAVIOR_FINDINGS_ENABLED:-false}
      AGENT_BEHAVIOR_ANALYSIS_REQUEST_ENABLED: ${AGENT_BEHAVIOR_ANALYSIS_REQUEST_ENABLED:-false}
      AGENT_GUARD_ALERT_ENABLED: ${AGENT_GUARD_ALERT_ENABLED:-false}
      AGENT_GUARD_ACTION_ENABLED: ${AGENT_GUARD_ACTION_ENABLED:-false}
      AGENT_GUARD_DENY_ENABLED: ${AGENT_GUARD_DENY_ENABLED:-false}
      AGENT_GUARD_FREEZE_ENABLED: ${AGENT_GUARD_FREEZE_ENABLED:-false}
      AGENT_GUARD_ACTION_PUBLISH_ENABLED: ${AGENT_GUARD_ACTION_PUBLISH_ENABLED:-false}
    ports:
      - "19092:19092"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 19092 || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s

  frontend:
    image: aegis-system/frontend:latest
    container_name: aegis-frontend
    restart: unless-stopped
    ports:
      - "80:80"
      - "8081:80"
    networks:
      - aegis-network
    healthcheck:
      test: ["CMD-SHELL", "wget --spider -q http://127.0.0.1/health || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 3

networks:
  aegis-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  minio_data:
    driver: local
  builder_data:
    driver: local
EOF
}

write_start_script() {
  cat > "${RELEASE_DIR}/start.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

log() {
  printf '[aegis-start] %s\n' "$*"
}

die() {
  printf '[aegis-start] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_positive_integer() {
  case "$2" in
    ''|*[!0-9]*) die "$1 must be a positive integer, got: $2" ;;
  esac
  [ "$2" -gt 0 ] || die "$1 must be a positive integer, got: $2"
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    die "Docker Compose is not available"
  fi
}

is_usable_ip() {
  case "$1" in
    ""|127.*|0.*|169.254.*) return 1 ;;
  esac
  return 0
}

is_virtual_iface() {
  case "$1" in
    lo|docker*|br-*|veth*|virbr*|cni*|flannel*|kube*|calico*|podman*) return 0 ;;
  esac
  return 1
}

detect_ip_from_default_route() {
  if command -v ip >/dev/null 2>&1; then
    for target in 1.1.1.1 8.8.8.8; do
      ip route get "${target}" 2>/dev/null | awk '
        {
          for (i = 1; i <= NF; i++) {
            if ($i == "src" && (i + 1) <= NF) {
              print $(i + 1)
              exit
            }
          }
        }'
    done
  fi
}

detect_ip_from_interfaces() {
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show scope global 2>/dev/null | while read -r _ iface _ cidr _; do
      if is_virtual_iface "${iface}"; then
        continue
      fi
      printf '%s\n' "${cidr%%/*}"
    done
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n'
  fi
}

detect_external_ip() {
  {
    detect_ip_from_default_route
    detect_ip_from_interfaces
  } | while read -r candidate; do
    if is_usable_ip "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
}

upsert_env() {
  key="$1"
  value="$2"
  env_file=".env"

  if [ ! -f "${env_file}" ]; then
    cp .env.example "${env_file}"
  fi

  if grep -q "^${key}=" "${env_file}"; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" "${env_file}"
    rm -f "${env_file}.bak"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >> "${env_file}"
  fi
}

load_images() {
  found=0
  for image in images/*.tar.gz; do
    [ -f "${image}" ] || continue
    found=1
    log "loading ${image}"
    gzip -dc "${image}" | docker load
  done

  [ "${found}" -eq 1 ] || die "no Docker image archives found in images/"
}

wait_for_postgres() {
  deadline=$((SECONDS + postgres_ready_timeout_seconds))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if compose exec -T postgres psql -U aegis_user -d aegis_db -Atc 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  die "postgres did not accept connections within ${postgres_ready_timeout_seconds} seconds"
}

release_schema_state() {
  compose exec -T postgres psql -U aegis_user -d aegis_db -Atc "
    WITH required_core_tables(table_name) AS (
      VALUES
        ('hosts'),
        ('aegis_rules'),
        ('task_logs'),
        ('vulnerabilities'),
        ('alerts'),
        ('block_policies'),
        ('sigma_rules')
    ), core_state AS (
      SELECT COUNT(*) FILTER (
        WHERE to_regclass('public.' || table_name) IS NOT NULL
      ) AS present_count,
      COUNT(*) AS required_count
      FROM required_core_tables
    )
    SELECT CASE
      WHEN present_count = required_count THEN 'ready'
      WHEN present_count = 0 THEN 'recoverable'
      ELSE 'partial'
    END
    FROM core_state
  "
}

bootstrap_recoverable_release_database() {
  schema_state="$(release_schema_state)" || die "could not inspect PostgreSQL schema state"
  case "${schema_state}" in
    ready)
      log "PostgreSQL schema is ready"
      ;;
    recoverable)
      log "detected a recoverable pre-bootstrap PostgreSQL schema; applying release init.sql"
      compose exec -T postgres psql -v ON_ERROR_STOP=1 -U aegis_user -d aegis_db \
        -f /docker-entrypoint-initdb.d/01-init.sql
      schema_state="$(release_schema_state)" || die "could not verify PostgreSQL schema after bootstrap"
      [ "${schema_state}" = "ready" ] || die "release database bootstrap completed without the required schema"
      log "PostgreSQL schema bootstrap completed"
      ;;
    partial)
      die "PostgreSQL has a partial schema; refusing automatic repair to protect data. For a failed fresh install, remove only this release's postgres_data volume and rerun start.sh."
      ;;
    *)
      die "unexpected PostgreSQL schema state: ${schema_state}"
      ;;
  esac
}

require_cmd docker
require_cmd gzip
require_cmd curl

docker info >/dev/null 2>&1 || die "Docker daemon is not available"

if [ ! -f .env.example ]; then
  die ".env.example is missing"
fi

external_ip="$(detect_external_ip | head -n 1 || true)"
if [ -z "${external_ip}" ]; then
  die "could not detect a usable local IP address; set EXTERNAL_IP manually in .env"
fi

upsert_env EXTERNAL_IP "${external_ip}"
log "wrote EXTERNAL_IP=${external_ip} to .env"

postgres_ready_timeout_seconds="${AEGIS_POSTGRES_READY_TIMEOUT_SECONDS:-180}"
api_health_timeout_seconds="${AEGIS_API_HEALTH_TIMEOUT_SECONDS:-300}"
initial_wait_seconds="${AEGIS_START_WAIT_SECONDS:-10}"
require_positive_integer "AEGIS_POSTGRES_READY_TIMEOUT_SECONDS" "${postgres_ready_timeout_seconds}"
require_positive_integer "AEGIS_API_HEALTH_TIMEOUT_SECONDS" "${api_health_timeout_seconds}"
require_positive_integer "AEGIS_START_WAIT_SECONDS" "${initial_wait_seconds}"

load_images
compose up -d postgres
wait_for_postgres
bootstrap_recoverable_release_database
compose up -d

log "waiting ${initial_wait_seconds}s before checking API health"
sleep "${initial_wait_seconds}"
compose ps

diagnose_start_failure() {
  log "deployment status at API health-check timeout:"
  compose ps -a || true

  for service in api-server server kafka postgres redis minio builder; do
    log "last ${AEGIS_START_LOG_TAIL:-120} log lines for ${service}:"
    compose logs --tail="${AEGIS_START_LOG_TAIL:-120}" "${service}" || true
  done
}

deadline=$((SECONDS + api_health_timeout_seconds))
next_progress_at=$SECONDS
api_healthy=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if curl -fsS --connect-timeout 1 --max-time 3 http://127.0.0.1:8082/health >/dev/null 2>&1; then
    log "api-server is healthy"
    api_healthy=1
    break
  fi

  if [ "$SECONDS" -ge "$next_progress_at" ]; then
    remaining=$((deadline - SECONDS))
    log "waiting for api-server health (up to ${remaining}s remaining)"
    next_progress_at=$((SECONDS + 10))
  fi

  sleep 2
done

if [ "${api_healthy}" -ne 1 ]; then
  diagnose_start_failure
  die "api-server did not become healthy within ${api_health_timeout_seconds} seconds; see service logs above"
fi

log "frontend: http://${external_ip}:8081"
log "api health: http://${external_ip}:8082/health"
EOF
  chmod +x "${RELEASE_DIR}/start.sh"
}

write_release_readme() {
  cat > "${RELEASE_DIR}/README.md" <<EOF
# Aegis ${VERSION} Offline Release

## Start

\`\`\`bash
chmod +x ./start.sh
./start.sh
\`\`\`

\`start.sh\` automatically detects a usable local IPv4 address and writes it to
\`.env\` as \`EXTERNAL_IP\` before starting Docker Compose. The API server and
agent hub read this value through \`SERVER_EXTERNAL_IP\`, so generated Agent
install commands point back to this host instead of an internal container IP.

All Docker images are stored in the single \`images/aegis-images.tar.gz\` archive
to preserve shared layers and reduce the overall release size.

The first startup can take several minutes while Kafka and the agent hub pass
their health checks. \`start.sh\` waits up to five minutes for the API by default.
Override that limit only when needed:

\`\`\`bash
AEGIS_API_HEALTH_TIMEOUT_SECONDS=600 ./start.sh
\`\`\`

Before starting application services, \`start.sh\` checks seven required core
PostgreSQL tables. If a failed first boot left all core tables absent, it replays
the included \`init.sql\` automatically, even when API Server already created
empty GORM-managed tables. If only some core tables exist, the database is never
changed automatically; the script stops and reports the recovery action instead.

On timeout, \`start.sh\` prints the Compose service states and the latest logs for
the API Server and its startup dependencies. Preserve that output when opening
a deployment issue.

## Useful Checks

\`\`\`bash
docker compose ps
curl http://localhost:8082/health
curl -s http://localhost:8082/api/v1/agent/install.sh | grep SERVER_ADDR
\`\`\`
EOF
}

copy_env_example() {
  cp "${ROOT_DIR}/.env.example" "${RELEASE_DIR}/.env.example"
}

normalize_release_permissions() {
  # A release may be produced by a CI runner with umask 0077. Normalize the
  # archive tree so Compose and unprivileged container users can traverse and
  # read bind-mounted files after extraction.
  find "${RELEASE_DIR}" -type d -exec chmod 0755 {} +
  find "${RELEASE_DIR}" -type f -exec chmod 0644 {} +
  chmod 0755 \
    "${RELEASE_DIR}/start.sh" \
    "${RELEASE_DIR}/build-context/minio-entrypoint.sh"

  if [ -f "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64" ]; then
    chmod 0755 "${RELEASE_DIR}/build-context/aegis-agent-linux-amd64"
  fi
}

require_local_image() {
  docker image inspect "$1" >/dev/null 2>&1 || die "required local image is missing: $1"
}

reuse_local_image() {
  local source_image="$1"
  local release_image="$2"
  local image_metadata

  require_local_image "${source_image}"
  image_metadata="$(docker image inspect --format '{{.Id}} created={{.Created}} platform={{.Os}}/{{.Architecture}}' "${source_image}")"
  info "using local image ${source_image} (${image_metadata}) as ${release_image}"
  if [ "${source_image}" != "${release_image}" ]; then
    docker tag "${source_image}" "${release_image}"
  fi
}

build_minio_with_agent_image() {
  info "building MinIO image with preloaded agent artifact"
  docker build --platform "${DOCKER_PLATFORM}" -f "${RELEASE_DIR}/Dockerfile.minio" -t aegis-system/minio-with-agent:latest "${RELEASE_DIR}"
}

prepare_local_images() {
  info "reusing local Linux AMD64 images for the release"
  reuse_local_image "${LOCAL_API_SERVER_IMAGE}" aegis-system/api-server:latest
  reuse_local_image "${LOCAL_SERVER_IMAGE}" aegis-system/server:latest
  reuse_local_image "${LOCAL_DC_IMAGE}" aegis-system/dc:latest
  reuse_local_image "${LOCAL_FRONTEND_IMAGE}" aegis-system/frontend:latest
  reuse_local_image "${LOCAL_MCP_GATEWAY_IMAGE}" "${MCP_GATEWAY_SERVICE_IMAGE}"

  for image in \
    "${AGENT_ARTIFACT_IMAGE}" \
    "${BUILDER_SERVICE_IMAGE}" \
    "${EBPF_BUILDER_IMAGE}" \
    pgvector/pgvector:pg16 \
    redis:7-alpine \
    confluentinc/cp-kafka:7.5.0 \
    confluentinc/cp-zookeeper:7.5.0 \
    minio/minio:latest \
    minio/mc:latest; do
    require_local_image "${image}"
  done

  extract_agent_artifact
  build_minio_with_agent_image
}

build_images() {
  info "building application images"
  docker build --platform "${DOCKER_PLATFORM}" -f "${ROOT_DIR}/api-server/Dockerfile" -t aegis-system/api-server:latest "${ROOT_DIR}/api-server"
  docker build --platform "${DOCKER_PLATFORM}" -f "${ROOT_DIR}/server/Dockerfile" -t aegis-system/server:latest "${ROOT_DIR}/server"
  docker build --platform "${DOCKER_PLATFORM}" -f "${ROOT_DIR}/dc/Dockerfile" -t aegis-system/dc:latest "${ROOT_DIR}/dc"
  docker build --platform "${DOCKER_PLATFORM}" -f "${ROOT_DIR}/frontend/Dockerfile" -t aegis-system/frontend:latest "${ROOT_DIR}/frontend"
  docker build --platform "${DOCKER_PLATFORM}" -f "${ROOT_DIR}/mcp-gateway/Dockerfile" -t "${MCP_GATEWAY_SERVICE_IMAGE}" "${ROOT_DIR}/mcp-gateway"
  build_builder_service_image

  info "pulling base images"
  docker pull pgvector/pgvector:pg16
  docker pull redis:7-alpine
  docker pull confluentinc/cp-kafka:7.5.0
  docker pull confluentinc/cp-zookeeper:7.5.0
  docker pull minio/minio:latest
  docker pull minio/mc:latest

  build_minio_with_agent_image
}

save_image() {
  image="$1"
  archive="$2"
  info "saving ${image} -> images/${archive}"
  docker save "${image}" | gzip > "${RELEASE_DIR}/images/${archive}"
}

save_combined_image_archive() {
  local compressor=(gzip -9)
  if command -v pigz >/dev/null 2>&1; then
    compressor=(pigz -9)
  fi

  info "saving all release images with shared-layer deduplication -> images/aegis-images.tar.gz"
  docker save \
    aegis-system/api-server:latest \
    aegis-system/server:latest \
    aegis-system/dc:latest \
    aegis-system/frontend:latest \
    "${MCP_GATEWAY_SERVICE_IMAGE}" \
    "${BUILDER_SERVICE_IMAGE}" \
    "${EBPF_BUILDER_IMAGE}" \
    aegis-system/minio-with-agent:latest \
    pgvector/pgvector:pg16 \
    redis:7-alpine \
    confluentinc/cp-kafka:7.5.0 \
    confluentinc/cp-zookeeper:7.5.0 \
    minio/minio:latest \
    minio/mc:latest |
    "${compressor[@]}" > "${RELEASE_DIR}/images/aegis-images.tar.gz"

  cat > "${RELEASE_DIR}/images/manifest.txt" <<EOF
aegis-system/api-server:latest
aegis-system/server:latest
aegis-system/dc:latest
aegis-system/frontend:latest
${MCP_GATEWAY_SERVICE_IMAGE}
${BUILDER_SERVICE_IMAGE}
${EBPF_BUILDER_IMAGE}
aegis-system/minio-with-agent:latest
pgvector/pgvector:pg16
redis:7-alpine
confluentinc/cp-kafka:7.5.0
confluentinc/cp-zookeeper:7.5.0
minio/minio:latest
minio/mc:latest
EOF
}

export_images() {
  if [ "${COMBINED_IMAGE_ARCHIVE}" = "1" ]; then
    save_combined_image_archive
    return
  fi

  save_image aegis-system/api-server:latest api-server.tar.gz
  save_image aegis-system/server:latest server.tar.gz
  save_image aegis-system/dc:latest dc.tar.gz
  save_image aegis-system/frontend:latest frontend.tar.gz
  save_image "${MCP_GATEWAY_SERVICE_IMAGE}" mcp-gateway.tar.gz
  save_image "${BUILDER_SERVICE_IMAGE}" builder.tar.gz
  save_image "${EBPF_BUILDER_IMAGE}" ebpf-builder-base.tar.gz
  save_image aegis-system/minio-with-agent:latest minio-with-agent.tar.gz
  save_image pgvector/pgvector:pg16 pgvector.tar.gz
  save_image redis:7-alpine redis.tar.gz
  save_image confluentinc/cp-kafka:7.5.0 kafka.tar.gz
  save_image confluentinc/cp-zookeeper:7.5.0 zookeeper.tar.gz
  save_image minio/minio:latest minio.tar.gz
  save_image minio/mc:latest minio-mc.tar.gz
}

zip_release() {
  confirm_replace_zip
  (
    cd "${RELEASE_ROOT}"
    zip -r "${ZIP_NAME}" "${VERSION}/"
  )
}

main() {
  validate_version
  prepare_release_dir
  write_minio_context
  write_init_sql
  copy_release_migration
  write_release_compose
  write_start_script
  write_release_readme
  copy_env_example
  normalize_release_permissions

  if [ "${GENERATE_ONLY:-0}" = "1" ]; then
    info "release files generated without building Docker images: ${RELEASE_DIR}"
    return
  fi

  require_cmd docker
  require_cmd gzip
  require_cmd zip
  docker info >/dev/null 2>&1 || die "Docker daemon is not available"

  case "${USE_LOCAL_IMAGES}" in
    0)
      build_agent_artifact
      build_images
      ;;
    1)
      prepare_local_images
      ;;
    *)
      die "USE_LOCAL_IMAGES must be 0 or 1, got: ${USE_LOCAL_IMAGES}"
      ;;
  esac
  export_images
  normalize_release_permissions
  zip_release

  info "release package created: ${ZIP_PATH}"
}

main "$@"
