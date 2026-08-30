import os
import time
import random
import logging
from confluent_kafka import Producer

# ==========================================
# ⚙️ CONFIGURABLE DIALS FOR SCALABILITY TEST
# ==========================================
EVENTS_PER_SECOND = 1000    # Target events per second (if BURST_MODE is False)
BURST_MODE = False        # If True, blasts logs as fast as possible (ignores EPS)
MALFORMED_PERCENTAGE = 20    # % of logs to randomly corrupt to test the Dead-Letter Queue

# Kafka Config
KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
TOPIC_RAW = 'raw-event'
LOG_FILE = 'dummy_logs.txt'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

producer = Producer({'bootstrap.servers': KAFKA_BROKER})

def delivery_report(err, msg):
    """Callback triggered on successful/failed delivery of message."""
    if err is not None:
        logger.error(f"Delivery failed: {err}")

def load_dummy_logs():
    """Loads dummy logs from a text file."""
    if not os.path.exists(LOG_FILE):
        logger.error(f"File '{LOG_FILE}' not found! Creating a basic one now...")
        default_logs = [
            "%ASA-2-106001: Inbound TCP connection denied from 192.168.1.50/4567 to 10.1.1.100/80 flags SYN on interface outside",
            "%ASA-3-313001: Denied ICMP type=8, code=0 from 10.10.10.10 on interface inside",
            "Sep  1 10:00:00 firewall pfSense: block in on eth0: 10.0.0.1:443 -> 192.168.1.100:12345"
        ]
        with open(LOG_FILE, 'w') as f:
            f.write("\n".join(default_logs))
        return default_logs

    with open(LOG_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    logs = load_dummy_logs()
    if not logs:
        return

    logger.info("="*50)
    logger.info(f"🚀 Starting Load Generator")
    logger.info(f"📊 Target EPS: {EVENTS_PER_SECOND}")
    logger.info(f"🔥 Burst Mode: {BURST_MODE}")
    logger.info(f"☠️  Malformed (Poison) Rate: {MALFORMED_PERCENTAGE}%")
    logger.info("="*50)
    
    try:
        events_sent = 0
        while True:
            # Pick a random log from our sample pool
            log_entry = random.choice(logs)
            
            # Simulate a malformed event (insert the word 'CORRUPT')
            if random.randint(1, 100) <= MALFORMED_PERCENTAGE:
                log_entry = f"CORRUPT - {log_entry}"

            # Produce to the raw topic
            producer.produce(TOPIC_RAW, value=log_entry.encode('utf-8'), callback=delivery_report)
            events_sent += 1
            
            if events_sent % 10 == 0:
                logger.info(f"Sent {events_sent} logs...")

            producer.poll(0) # Serves delivery callback queue
            
            # Control throughput
            if not BURST_MODE:
                time.sleep(1.0 / EVENTS_PER_SECOND)
                
    except KeyboardInterrupt:
        logger.info("\n🛑 Stopping load generator (Keyboard Interrupt).")
    finally:
        logger.info("Flushing remaining messages in queue...")
        producer.flush()
        logger.info("Done.")

if __name__ == '__main__':
    main()
