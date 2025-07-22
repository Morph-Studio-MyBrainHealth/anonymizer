import json
import logging
import os
import datetime
from cryptography.fernet import Fernet

from sqlalchemy import create_engine, URL
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Environment variables
db_secret_name = os.getenv('MYSQL_DB_SECRET_NAME', 'z/sandbox/clientconfig/mysql')
db_region_name = os.getenv('AWS_DB_REGION', 'us-east-2')
encryption_key = os.getenv('HIPAA_ENCRYPTION_KEY', None)
USE_LOCAL_DB = os.getenv('USE_LOCAL_DB', 'true').lower() == 'true'

Session = None
_encryption_cipher = None


def get_encryption_cipher():
    """Get or create encryption cipher for HIPAA compliance"""
    global _encryption_cipher
    if _encryption_cipher is None:
        if encryption_key:
            _encryption_cipher = Fernet(encryption_key.encode())
        else:
            # Generate a key for testing - in production, use KMS or secure key management
            key = Fernet.generate_key()
            _encryption_cipher = Fernet(key)
            logger.warning("Using generated encryption key - not for production use!")
    return _encryption_cipher


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data for HIPAA compliance"""
    if not data:
        return data
    cipher = get_encryption_cipher()
    return cipher.encrypt(data.encode()).decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    if not encrypted_data:
        return encrypted_data
    cipher = get_encryption_cipher()
    return cipher.decrypt(encrypted_data.encode()).decode()


def get_db_secrets():
    """Return database configuration for local testing"""
    if USE_LOCAL_DB:
        return {
            'host': 'localhost',
            'username': 'test',
            'password': 'test',
            'phidbname': 'test_anonymizer'
        }
    
    # Production would use AWS Secrets Manager
    # Not implemented for local testing
    raise NotImplementedError("AWS Secrets Manager not configured for local testing")


def create_db_engine(db_conn_string, debug_mode=False):
    """Create database engine"""
    if USE_LOCAL_DB:
        # SQLite for local testing
        return create_engine(
            db_conn_string,
            echo=debug_mode,
            connect_args={'check_same_thread': False}  # Needed for SQLite
        )
    else:
        # MySQL for production
        return create_engine(
            db_conn_string,
            echo=debug_mode,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600,
            pool_pre_ping=True,
            pool_use_lifo=True,
            poolclass=QueuePool
        )


def create_db_session(engine):
    global Session
    if not Session:
        Session = sessionmaker(
            bind=engine,
            expire_on_commit=False,
            autoflush=False
        )
    return Session()


def get_db_session():
    global Session
    if not Session:
        if USE_LOCAL_DB:
            # Use SQLite for local testing
            database_url = "sqlite:///test_anonymizer.db"
            logger.info("Using SQLite database for local testing")
            
            engine = create_db_engine(database_url)
            
            # Create tables if they don't exist
            from db_objects import metadata
            metadata.create_all(engine)
            
            Session = sessionmaker(bind=engine)
        else:
            # Production MySQL configuration
            logger.info(f'Retrieving database access information')
            
            try:
                secrets = get_db_secrets()
            except:
                logger.error("Failed to get database secrets")
                raise
            
            db_name = secrets['phidbname']
            
            database_url = URL.create(
                drivername="mysql+pymysql",
                username=secrets['username'],
                host=secrets['host'],
                database=db_name,
                port=int(secrets.get('port', 3306)),
                password=secrets['password'],
                query={
                    'charset': 'utf8mb4',
                    'use_unicode': 'true'
                }
            )

            logger.info(f'Creating SQLAlchemy database engine for database: "{db_name}"')
            engine = create_db_engine(database_url)
            Session = sessionmaker(bind=engine)
        
    return Session()


def test_db_connection():
    """Test database connection for health checks"""
    try:
        session = get_db_session()
        session.execute("SELECT 1")
        session.close()
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {str(e)}")
        return False


def get_db_engine():
    """Get the database engine directly"""
    session = get_db_session()
    return session.bind


def export_user_data(masterid: str) -> dict:
    """Export all user data for GDPR compliance"""
    from db_objects import piimaster_table, piidata_table, piientity_table
    
    session = get_db_session()
    try:
        user_data = {
            'export_date': datetime.datetime.utcnow().isoformat(),
            'masterid': masterid,
            'piimaster': [],
            'piidata': [],
            'piientity': []
        }
        
        # Get master record
        master_query = piimaster_table.select().where(piimaster_table.c.uuid == masterid)
        master_result = session.execute(master_query).fetchall()
        for row in master_result:
            user_data['piimaster'].append(dict(row._asdict()))
        
        # Get PII data records
        data_query = piidata_table.select().where(piidata_table.c.uuid == masterid)
        data_result = session.execute(data_query).fetchall()
        for row in data_result:
            record = dict(row._asdict())
            user_data['piidata'].append(record)
        
        # Get PII entity records
        entity_query = piientity_table.select().where(piientity_table.c.uuid == masterid)
        entity_result = session.execute(entity_query).fetchall()
        for row in entity_result:
            record = dict(row._asdict())
            user_data['piientity'].append(record)
        
        return user_data
        
    finally:
        session.close()


def delete_user_data(masterid: str) -> bool:
    """Delete all user data for GDPR Article 17 compliance"""
    from db_objects import piimaster_table, piidata_table, piientity_table
    
    session = get_db_session()
    try:
        # Delete in order due to foreign key constraints
        session.execute(piidata_table.delete().where(piidata_table.c.uuid == masterid))
        session.execute(piientity_table.delete().where(piientity_table.c.uuid == masterid))
        session.execute(piimaster_table.delete().where(piimaster_table.c.uuid == masterid))
        
        session.commit()
        logger.info(f"User data deleted for masterid: {masterid}")
        return True
        
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to delete user data: {str(e)}")
        return False
    finally:
        session.close()
