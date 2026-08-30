import os
import json
import logging
import signal
import sys
from confluent_kafka import Consumer, Producer, KafkaError, KafkaException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurable settings
KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
GROUP_ID = 'python-worker-group'

# Topics
TOPIC_RAW = 'raw-event'
TOPIC_NORMALIZED = 'normalized-event'
TOPIC_DLQ = 'dead-letter-topic'

# --- Mock Functions (Pending team contracts) ---
def mock_parser(raw_data):
    """Simulates parsing a raw string. Throws ValueError if it encounters 'CORRUPT'."""
    if "CORRUPT" in raw_data:
        raise ValueError("Poison event detected during parsing: Corrupt data format.")
    return {"parsed": True, "original_length": len(raw_data), "data": raw_data}

def mock_normalizer(parsed_data):
    """Simulates normalizing the dictionary into OCSF schema."""
    return {"schema": "OCSF", "normalized": True, "event": parsed_data}

# --- Kafka Setup ---
consumer_conf = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': GROUP_ID,
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False  # Explicit offset commit for reliability
}

producer_conf = {
    'bootstrap.servers': KAFKA_BROKER
}

consumer = Consumer(consumer_conf)
producer = Producer(producer_conf)

running = True

def signal_handler(sig, frame):
    """Handles graceful shutdown on SIGINT (Ctrl+C) / SIGTERM"""
    global running
    logger.info("Shutdown signal received. Finishing current event and shutting down gracefully...")
    running = False

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def delivery_report(err, msg):
    """Called once for each message produced to indicate delivery result."""
    if err is not None:
        logger.error(f"Message delivery failed: {err}")
    else:
        logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}] at offset {msg.offset()}")

def process_messages():
    try:
        consumer.subscribe([TOPIC_RAW])
        logger.info(f"Subscribed to topic '{TOPIC_RAW}'. Waiting for messages...")

        while running:
            # Poll for new messages
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # End of partition event
                    continue
                else:
                    logger.error(f"Consumer error: {msg.error()}")
                    break

            # Decode the raw string
            raw_value = msg.value().decode('utf-8')
            logger.info(f"Consumed raw event: {raw_value}")

            try:
                # 1. Parse
                parsed = mock_parser(raw_value)
                
                # 2. Normalize
                normalized = mock_normalizer(parsed)
                
                # 3. Produce to Normalized Topic
                producer.produce(
                    TOPIC_NORMALIZED, 
                    value=json.dumps(normalized).encode('utf-8'),
                    callback=delivery_report
                )
                logger.info("Successfully processed and forwarded to normalized topic.")

            except Exception as e:
                # Dead-Letter Queue (DLQ) Logic
                logger.error(f"Processing failed: {e}. Routing original payload to DLQ.")
                producer.produce(
                    TOPIC_DLQ, 
                    value=raw_value.encode('utf-8'),
                    callback=delivery_report
                )
            
            # Flush producer and manually commit offset exactly once AFTER processing
            producer.poll(0)
            consumer.commit(asynchronous=False)

    except KafkaException as e:
        logger.error(f"Kafka exception: {e}")
    finally:
        # Graceful shutdown steps
        logger.info("Flushing producer...")
        producer.flush()
        logger.info("Closing consumer...")
        consumer.close()
        logger.info("Worker stopped safely. State saved.")

if __name__ == '__main__':
    process_messages()
