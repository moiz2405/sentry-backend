import os
import time
import logging
import clickhouse_connect
from clickhouse_connect.driver.client import Client

logger = logging.getLogger(__name__)

def get_clickhouse_client() -> Client:
    """Initialize and return a ClickHouse client."""
    host = os.environ.get("CLICKHOUSE_HOST", "localhost")
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    username = os.environ.get("CLICKHOUSE_USER", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    database = os.environ.get("CLICKHOUSE_DB", "otel")

    # Retry logic for when docker compose is just starting
    for _ in range(5):
        try:
            client = clickhouse_connect.get_client(
                host=host,
                port=port,
                username=username,
                password=password,
                database=database
            )
            return client
        except Exception as e:
            logger.warning(f"Failed to connect to ClickHouse: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            
    raise Exception("Could not connect to ClickHouse after 5 retries.")


def init_db():
    """Create necessary databases and tables if they don't exist."""
    print("Initialising ClickHouse schema...")
    try:
        # We need a client without DB specified first to create the DB
        setup_client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", "")
        )
        setup_client.command("CREATE DATABASE IF NOT EXISTS otel")
        
        # Now connect specifically to our DB
        client = get_clickhouse_client()
        
        # Create a basic logs table if relying on our own ingestion,
        # otherwise otel-collector will create them.
        # It's good practice to pre-create it to avoid race conditions.
        client.command('''
            CREATE TABLE IF NOT EXISTS otel_logs (
                Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
                TraceId String,
                SpanId String,
                SeverityText String,
                SeverityNumber Int32,
                ServiceName String,
                Body String,
                ResourceAttributes Map(String, String),
                LogAttributes Map(String, String)
            ) ENGINE = MergeTree
            ORDER BY (ServiceName, SeverityText, Timestamp)
            TTL toDateTime(Timestamp) + INTERVAL 7 DAY
        ''')
        print("ClickHouse schema initialisation complete.")
    except Exception as e:
        logger.error(f"Failed to initialise ClickHouse schema: {e}")
        
if __name__ == "__main__":
    init_db()
