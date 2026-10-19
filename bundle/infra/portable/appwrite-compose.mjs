// Appwrite 2.4 topology from appwrite/appwrite@eac5bdef1b2c45b61cd4ca706dee1186b25b8031.
// Pure renderer shared by the compatibility lab and portable hosting profile.
import { createHash } from "node:crypto";
export const IMAGES = Object.freeze({
  appwrite: 'appwrite/appwrite:2.4.0',
  postgresql: 'appwrite/postgres:0.1.0',
  redis: 'redis:7.4.7-alpine',
  clickhouse: 'clickhouse/clickhouse-server:26.4.3-alpine',
  executor: 'openruntimes/executor:0.29.0',
  orchestrator: 'ghcr.io/open-runtimes/orchestrator/orchestrator:2.2.2',
  jobSidecar: 'ghcr.io/open-runtimes/orchestrator/job-sidecar:2.2.2',
  geo: 'appwrite/geo:0.3.2',
  python: 'openruntimes/python:v5-3.12',
});
const OWNER = "io.appwritework.r0";
const VOLUMES = ['postgresql', 'redis', 'clickhouse', 'uploads', 'imports', 'cache', 'config', 'certificates', 'functions', 'sites', 'builds'];
const executorHostname = state => "r0e-" + createHash("sha256").update(state.project).digest("hex").slice(0,10);
export function buildCompose(state, pins = {}) {
  const image = (key) => pins[key]?.reference ?? IMAGES[key];
  const labels = { [OWNER]: state.runId };
  const network = `${state.project}-network`;
  const common = {
    restart: 'no', labels, networks: ['lab'],
    logging: { driver: 'json-file', options: { 'max-size': '5m', 'max-file': '2' } },
  };
  const publicEnv = {
    _APP_ENV: 'production', _APP_EDITION: 'self-hosted', _APP_LOCALE: 'en',
    _APP_WORKER_PER_CORE: '1', _APP_WORKERS_NUM: '1', _APP_WORKER_MAX_COROUTINES: '78',
    _APP_OPTIONS_ABUSE: 'disabled', _APP_OPTIONS_FORCE_HTTPS: 'disabled',
    _APP_OPTIONS_ROUTER_FORCE_HTTPS: 'disabled', _APP_OPTIONS_ROUTER_PROTECTION: 'disabled',
    _APP_DOMAIN: 'localhost', _APP_CONSOLE_DOMAIN: 'localhost',
    _APP_CONSOLE_HOSTNAMES: 'localhost,127.0.0.1', _APP_CONSOLE_SCHEMA: 'appwriteio',
    _APP_CONSOLE_WHITELIST_ROOT: 'enabled', _APP_CONSOLE_SESSION_ALERTS: 'disabled',
    _APP_DOMAIN_FUNCTIONS: 'functions.localhost', _APP_DOMAIN_SITES: 'sites.localhost',
    _APP_OPENSSL_KEY_V1: '${R0_OPENSSL_KEY}', _APP_NOTIFICATIONS_TRACKING_SECRET: '${R0_OPENSSL_KEY}',
    _APP_DB_ADAPTER: 'postgresql', _APP_DB_HOST: 'postgresql', _APP_DB_PORT: '5432',
    _APP_DB_SCHEMA: 'appwrite', _APP_DB_USER: 'appwrite', _APP_DB_PASS: '${R0_DB_PASSWORD}',
    _APP_DB_ADAPTER_DOCUMENTSDB: 'mongodb', _APP_DB_HOST_DOCUMENTSDB: 'disabled-mongodb',
    _APP_DB_ADAPTER_VECTORSDB: 'postgresql', _APP_DB_HOST_VECTORSDB: 'postgresql', _APP_DB_PORT_VECTORSDB: '5432',
    _APP_REDIS_HOST: 'redis', _APP_REDIS_PORT: '6379', _APP_REDIS_USER: '', _APP_REDIS_PASS: '',
    _APP_USAGE_STATS: 'enabled', _APP_USAGE_PASS: '${R0_CLICKHOUSE_PASSWORD}',
    _APP_CONNECTIONS_DB_USAGE: 'http://appwrite:${R0_CLICKHOUSE_PASSWORD}@clickhouse:8123/appwrite',
    _APP_CONNECTIONS_DB_EXECUTIONS: 'http://appwrite:${R0_CLICKHOUSE_PASSWORD}@clickhouse:8123/appwrite',
    _APP_POOL_SIZE_USAGE: '2', _APP_POOL_SIZE_EXECUTIONS: '2',
    _APP_STORAGE_DEVICE: 'Local', _APP_STORAGE_ANTIVIRUS: 'disabled',
    _APP_STORAGE_LIMIT: '30000000', _APP_STORAGE_PREVIEW_LIMIT: '20000000',
    _APP_COMPUTE_SIZE_LIMIT: '30000000', _APP_COMPUTE_BUILD_SIZE_LIMIT: '2000000000',
    _APP_COMPUTE_CPUS: '2', _APP_COMPUTE_MEMORY: '2048', _APP_COMPUTE_BUILD_TIMEOUT: '300',
    _APP_FUNCTIONS_TIMEOUT: '60', _APP_FUNCTIONS_RUNTIMES: 'python-3.12', _APP_SITES_RUNTIMES: '',
    _APP_EXECUTOR_HOST: 'http://executor/v1', _APP_EXECUTOR_SECRET: '${R0_EXECUTOR_SECRET}',
    _APP_JOBS_HOST: 'http://orchestrator:8080', _APP_JOBS_ENDPOINT: 'http://appwrite', _APP_JOBS_SECRET: '${R0_JOBS_SECRET}',
    _APP_BUILDS_VOLUME: `${state.project}-builds`, _APP_MIGRATION_HOST: 'appwrite',
    _APP_COMPUTE_RUNTIMES_NETWORK: network, _APP_EXECUTOR_IMAGES: image('python'),
    _APP_GEO_ENDPOINT: 'http://geo/v1', _APP_GEO_SECRET: '${R0_GEO_SECRET}',
    _APP_EMBEDDING: 'disabled', _APP_PWNED_PASSWORDS_DSN: 'none://localhost',
    _APP_PROJECT_REGIONS: 'default', _APP_LOGGING_FORMAT: 'json', _APP_LOGGING_CONFIG: '',
    _APP_DNS_EXTERNAL: '127.0.0.11', _APP_ALLOWED_INTERNAL_ADDRESSES: '127.0.0.1,::1',
    _APP_OPEN_RUNTIMES_NFT: 'disabled',
  };
  const storage = ['uploads', 'imports', 'cache', 'config', 'certificates', 'functions', 'sites', 'builds'].map((name) => `${name}:/storage/${name}`);
  const health = (test) => ({ test, interval: '5s', timeout: '5s', retries: 30, start_period: '15s' });
  const depends = Object.fromEntries(['postgresql', 'redis', 'clickhouse', 'geo', 'executor'].map((name) => [name, { condition: 'service_healthy' }]));
  return {
    name: state.project,
    services: {
      postgresql: { ...common, image: image('postgresql'), environment: { POSTGRES_DB: 'appwrite', POSTGRES_USER: 'appwrite', POSTGRES_PASSWORD: '${R0_DB_PASSWORD}' }, volumes: ['postgresql:/var/lib/postgresql'], healthcheck: health(['CMD', 'pg_isready', '-U', 'appwrite', '-d', 'appwrite']) },
      redis: { ...common, image: image('redis'), command: ['redis-server', '--maxmemory', '512mb', '--maxmemory-policy', 'allkeys-lru'], volumes: ['redis:/data'], healthcheck: health(['CMD', 'redis-cli', 'ping']) },
      clickhouse: {
        ...common, image: image('clickhouse'), environment: { CLICKHOUSE_DB: 'appwrite', CLICKHOUSE_USER: 'appwrite', CLICKHOUSE_PASSWORD: '${R0_CLICKHOUSE_PASSWORD}', CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: '1', CLICKHOUSE_ALWAYS_RUN_INITDB_SCRIPTS: '1' },
        volumes: ['clickhouse:/var/lib/clickhouse', './clickhouse-config.xml:/etc/clickhouse-server/config.d/appwrite.xml:ro', './clickhouse-init.sh:/docker-entrypoint-initdb.d/clickhouse-init.sh:ro'],
        ulimits: { nofile: { soft: 262144, hard: 262144 } },
        healthcheck: health(['CMD-SHELL', 'clickhouse-client --user "$$CLICKHOUSE_USER" --password "$$CLICKHOUSE_PASSWORD" --query "SELECT 1" >/dev/null']),
      },
      geo: { ...common, image: image('geo'), environment: { GEO_SECRET: '${R0_GEO_SECRET}' }, healthcheck: health(['CMD-SHELL', 'php -r "exit(json_decode(file_get_contents(\'http://localhost/v1/health\'))->status === \'ok\' ? 0 : 1);"']) },
      executor: {
        ...common, image: image('executor'), container_name: executorHostname(state), hostname: executorHostname(state), stop_signal: 'SIGINT',
        volumes: ['/var/run/docker.sock:/var/run/docker.sock', 'builds:/storage/builds', 'functions:/storage/functions', 'sites:/storage/sites', '/tmp:/tmp:rw'],
        // Executor 0.29.0 unconditionally pulls this list at startup. Its advertised
        // OPR_EXECUTOR_IMAGE_PULL switch is not read by app/src. Pull the digest,
        // not the mutable catalog tag; still verify actual runtime child image IDs.
        environment: { OPR_EXECUTOR_IMAGES: image('python'), OPR_EXECUTOR_NETWORK: network, OPR_EXECUTOR_ENV: 'development', OPR_EXECUTOR_RUNTIMES: 'python-3.12', OPR_EXECUTOR_SECRET: '${R0_EXECUTOR_SECRET}', OPR_EXECUTOR_RUNTIME_VERSIONS: 'v5', OPR_EXECUTOR_INACTIVE_THRESHOLD: '60', OPR_EXECUTOR_MAINTENANCE_INTERVAL: '30', OPR_EXECUTOR_CONNECTION_STORAGE: 'local://localhost', OPR_EXECUTOR_CONNECTION_BUILD_CACHE_STORAGE: '', OPEN_RUNTIMES_NFT: 'disabled' },
        healthcheck: health(['CMD-SHELL', 'curl -fsS -H "Authorization: Bearer $$OPR_EXECUTOR_SECRET" http://localhost/v1/health >/dev/null']),
      },
      orchestrator: {
        ...common, image: image('orchestrator'), user: 'root', hostname: `${state.project}-orchestrator`,
        volumes: ['/var/run/docker.sock:/var/run/docker.sock', './jobs-key.private:/run/secrets/jobs-key:ro'],
        environment: { ORCHESTRATOR_BACKEND: 'docker', ORCHESTRATOR_NETWORK: network, DOCKER_NETWORK: network, ARTIFACT_ENDPOINT: 'http://orchestrator:8080', API_KEY_FILE: '/run/secrets/jobs-key', JOB_SIDECAR_IMAGE: image('jobSidecar') },
        healthcheck: health(['CMD', 'orchestrator', '-check-ready']),
      },
      appwrite: { ...common, image: image('appwrite'), environment: publicEnv, volumes: storage, depends_on: { ...depends, orchestrator: { condition: 'service_started' } }, ports: ['127.0.0.1::80'], healthcheck: health(['CMD-SHELL', 'curl -fsS -o /dev/null -H "Host: localhost" http://localhost/v1/health/version']) },
      worker: { ...common, image: image('appwrite'), entrypoint: ['worker'], environment: publicEnv, volumes: storage, depends_on: { ...depends, orchestrator: { condition: 'service_started' } } },
    },
    networks: { lab: { name: network, driver: 'bridge', labels } },
    volumes: Object.fromEntries(VOLUMES.map((name) => [name, { name: `${state.project}-${name}`, labels }])),
  };
}
