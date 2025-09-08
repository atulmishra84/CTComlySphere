"""
Database migration to add classification and controls fields to AIAgentInventory table
Run this once to upgrade the existing database schema
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_inventory_table():
    """Add new columns to AIAgentInventory table"""
    with app.app_context():
        try:
            # Create a connection to execute raw SQL
            connection = db.engine.connect()
            
            # List of new columns to add
            new_columns = [
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS primary_classification VARCHAR(100)",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS secondary_classifications JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS classification_confidence FLOAT",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS classification_reasons JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS applicable_frameworks JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS required_controls JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS applied_controls JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS failed_controls JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS control_status JSON",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS last_classification_update TIMESTAMP",
                "ALTER TABLE ai_agent_inventory ADD COLUMN IF NOT EXISTS classification_version VARCHAR(50) DEFAULT '1.0'"
            ]
            
            logger.info("Starting database migration for AIAgentInventory table...")
            
            for sql in new_columns:
                try:
                    connection.execute(db.text(sql))
                    logger.info(f"Successfully executed: {sql}")
                except Exception as e:
                    logger.warning(f"Column might already exist or error occurred: {str(e)}")
            
            connection.commit()
            logger.info("Database migration completed successfully!")
            
        except Exception as e:
            logger.error(f"Migration failed: {str(e)}")
            raise
        finally:
            if 'connection' in locals():
                connection.close()

if __name__ == "__main__":
    migrate_inventory_table()