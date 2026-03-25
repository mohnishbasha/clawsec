import logging
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from prometheus_client import start_http_server
import os

logger = logging.getLogger(__name__)


def setup_telemetry(service_name: str = "clawsec", otlp_endpoint: str = None):
    """
    Initialize OpenTelemetry tracing, metrics, and logs.

    Sets up:
    - OTLP gRPC span exporter → OTel Collector (traces)
    - Prometheus metrics reader (scrape endpoint on port 9090)
    - OTLP gRPC log exporter → OTel Collector → VictoriaLogs (logs)
    - Python root logger bridged to OTel LoggerProvider

    Args:
        service_name: Logical service name embedded in all telemetry signals.
        otlp_endpoint: Override for OTLP collector endpoint. Falls back to the
                       OTLP_ENDPOINT env var and then to http://otel-collector:4317.
    """
    otlp_endpoint = otlp_endpoint or os.getenv("OTLP_ENDPOINT", "http://otel-collector:4317")

    # --- Trace provider ---
    tracer_provider = TracerProvider()
    try:
        otlp_span_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        tracer_provider.add_span_processor(BatchSpanProcessor(otlp_span_exporter))
        logger.info(f"OTLP trace exporter configured: {otlp_endpoint}")
    except Exception as exc:
        logger.warning(
            f"Could not configure OTLP trace exporter ({otlp_endpoint}): {exc}. "
            "Traces will not be exported."
        )
    trace.set_tracer_provider(tracer_provider)

    # --- Metrics provider with Prometheus ---
    try:
        prometheus_reader = PrometheusMetricReader()
        meter_provider = MeterProvider(metric_readers=[prometheus_reader])
        metrics.set_meter_provider(meter_provider)
        logger.info("Prometheus metric reader configured.")
    except Exception as exc:
        logger.warning(f"Could not configure Prometheus metric reader: {exc}.")
        meter_provider = MeterProvider()
        metrics.set_meter_provider(meter_provider)

    # --- Log provider → OTel Collector → VictoriaLogs ---
    try:
        otlp_log_exporter = OTLPLogExporter(endpoint=otlp_endpoint, insecure=True)
        logger_provider = LoggerProvider()
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_log_exporter))
        set_logger_provider(logger_provider)
        # Bridge Python root logger to OTel so all app logs are shipped
        otel_handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
        logging.getLogger().addHandler(otel_handler)
        logger.info(f"OTLP log exporter configured: {otlp_endpoint} → VictoriaLogs")
    except Exception as exc:
        logger.warning(
            f"Could not configure OTLP log exporter ({otlp_endpoint}): {exc}. "
            "Logs will not be shipped to VictoriaLogs."
        )

    tracer = trace.get_tracer(service_name)
    meter = metrics.get_meter(service_name)

    # --- Start Prometheus HTTP server ---
    try:
        start_http_server(9090)
        logger.info("Prometheus metrics server started on :9090")
    except OSError:
        # Already started (e.g. multiple workers or test reruns)
        logger.debug("Prometheus HTTP server already running on :9090 — skipping.")
    except Exception as exc:
        logger.warning(f"Could not start Prometheus HTTP server: {exc}")

    return tracer, meter
