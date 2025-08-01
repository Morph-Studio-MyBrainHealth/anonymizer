"""
Database methods for PII/PHI anonymization system
Thread-safe version with proper session management
Updated to only track HIPAA identifiers
"""

import uuid
import json
import logging
from datetime import datetime, timedelta
from sqlalchemy import text

import db_utils

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_piimaster_uuid(identity, identityType, insert=True):
    """
    Get or create a master UUID for the given identity.
    
    Args:
        identity: The identifier (e.g., user ID, email)
        identityType: The type of identifier
        insert: Whether to create a new record if not found
    
    Returns:
        The master UUID string
    """
    session = db_utils.get_db_session()
    try:
        # Check if identity already exists
        query = """
            SELECT uuid FROM PIIMaster 
            WHERE identity = %s AND identityType = %s
        """
        result = session.execute(query, (identity, identityType))
        row = result.fetchone()
        
        if row:
            return row['uuid']
        
        if insert:
            # Create new UUID
            master_uuid = str(uuid.uuid4())
            insert_query = """
                INSERT INTO PIIMaster (uuid, identity, identityType, created_at)
                VALUES (%s, %s, %s, %s)
            """
            session.execute(insert_query, 
                          (master_uuid, identity, identityType, datetime.utcnow()))
            session.commit()
            return master_uuid
        
        return None
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error in get_piimaster_uuid: {e}")
        raise
    finally:
        session.close()


def get_piientity_data(masterid):
    """
    Get all PII entity mappings for a master ID.
    
    Args:
        masterid: The master UUID
    
    Returns:
        List of dictionaries with PII mappings
    """
    session = db_utils.get_db_session()
    try:
        query = """
            SELECT piiType, originalData, fakeDataType, fakeData
            FROM PIIEntity
            WHERE uuid = %s
        """
        result = session.execute(query, (masterid,))
        
        rows = []
        for row in result:
            rows.append({
                'piiType': row['piiType'],
                'originalData': row['originalData'],
                'fakeDataType': row['fakeDataType'],
                'fakeData': row['fakeData']
            })
        
        return rows
        
    except Exception as e:
        logger.error(f"Error in get_piientity_data: {e}")
        return []
    finally:
        session.close()


def bulk_insert_piientity(records):
    """
    Bulk insert PII entity records.
    
    Args:
        records: List of dictionaries with PII entity data
    """
    session = db_utils.get_db_session()
    try:
        for record in records:
            # Check if record already exists
            check_query = """
                SELECT COUNT(*) as count FROM PIIEntity
                WHERE uuid = %s AND piiType = %s AND originalData = %s
            """
            result = session.execute(check_query, 
                                   (record['uuid'], record['piiType'], record['originalData']))
            
            if result.fetchone()['count'] == 0:
                # Insert new record
                insert_query = """
                    INSERT INTO PIIEntity (uuid, piiType, originalData, fakeDataType, fakeData, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                session.execute(insert_query,
                              (record['uuid'], record['piiType'], record['originalData'],
                               record['fakeDataType'], record['fakeData'], datetime.utcnow()))
        
        session.commit()
        logger.info(f"Successfully inserted {len(records)} PII entity records")
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error in bulk_insert_piientity: {e}")
        raise
    finally:
        session.close()


def insert_piidata(masterid, original, anonymized, method, metadata=None):
    """
    Insert a record of anonymization/de-anonymization operation.
    
    Args:
        masterid: The master UUID
        original: Original data
        anonymized: Anonymized data
        method: The method used (ANONYMIZE, DE-ANONYMIZE, etc.)
        metadata: Additional metadata as JSON string
    """
    session = db_utils.get_db_session()
    try:
        insert_query = """
            INSERT INTO PIIData (uuid, originalData, anonymizedData, method, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        session.execute(insert_query,
                      (masterid, original, anonymized, method, metadata, datetime.utcnow()))
        session.commit()
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error in insert_piidata: {e}")
        raise
    finally:
        session.close()


def get_anonymization_statistics(masterid=None):
    """
    Get anonymization statistics for a user or globally.
    Updated to only track HIPAA identifiers.
    """
    session = db_utils.get_db_session()
    try:
        # HIPAA Safe Harbor identifiers (18 types)
        hipaa_identifiers = [
            # Core identifiers
            'NAME', 'EMAIL', 'PHONE_NUMBER', 'SSN', 'ADDRESS', 'DATE', 'DOB', 'ZIP',
            # ID numbers
            'MRN', 'INSURANCE_ID', 'LICENSE_NUMBER', 'EMPLOYEE_ID',
            # Technical identifiers
            'CREDIT_DEBIT_NUMBER', 'URL', 'IP_ADDRESS', 'DEVICE_ID', 'VEHICLE_ID',
            # Other
            'BIOMETRIC_ID', 'CLINICAL_TRIAL_ID', 'OTHER'
        ]
        
        if masterid:
            # Get statistics for specific user
            query = """
                SELECT piiType, COUNT(*) as count 
                FROM PIIEntity 
                WHERE uuid = %s 
                GROUP BY piiType
            """
            result = session.execute(query, (masterid,))
        else:
            # Get global statistics
            query = """
                SELECT piiType, COUNT(*) as count 
                FROM PIIEntity 
                GROUP BY piiType
            """
            result = session.execute(query)
        
        # Process results
        entity_types = {}
        total_entities = 0
        hipaa_entities = 0
        
        for row in result:
            pii_type = row['piiType']
            count = row['count']
            
            # Only count HIPAA identifiers
            if pii_type in hipaa_identifiers:
                entity_types[pii_type] = count
                total_entities += count
                hipaa_entities += count
        
        # Get additional statistics from PIIData table
        if masterid:
            data_query = """
                SELECT method, COUNT(*) as count 
                FROM PIIData 
                WHERE uuid = %s 
                GROUP BY method
            """
            data_result = session.execute(data_query, (masterid,))
        else:
            data_query = """
                SELECT method, COUNT(*) as count 
                FROM PIIData 
                GROUP BY method
            """
            data_result = session.execute(data_query)
        
        operations = {}
        for row in data_result:
            operations[row['method']] = row['count']
        
        return {
            'total_entities': total_entities,
            'hipaa_entities': hipaa_entities,
            'entity_types': entity_types,
            'operations': operations,
            'summary': {
                'unique_entity_types': len(entity_types),
                'anonymizations': operations.get('ANONYMIZE', 0) + 
                                operations.get('ANONYMIZE_JSON', 0) + 
                                operations.get('ANONYMIZE_JSON_SIMPLE', 0),
                'de_anonymizations': operations.get('DE-ANONYMIZE', 0) + 
                                   operations.get('DE_ANONYMIZE_JSON', 0) + 
                                   operations.get('DE_ANONYMIZE_JSON_SIMPLE', 0)
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting anonymization statistics: {e}")
        return {
            'total_entities': 0,
            'hipaa_entities': 0,
            'entity_types': {},
            'error': str(e)
        }
    finally:
        session.close()


def cleanup_old_records(days=90):
    """
    Clean up old anonymization records.
    
    Args:
        days: Number of days to keep records
    """
    session = db_utils.get_db_session()
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old PIIData records
        delete_data_query = """
            DELETE FROM PIIData 
            WHERE created_at < %s
        """
        result = session.execute(delete_data_query, (cutoff_date,))
        data_deleted = result.rowcount
        
        # Delete orphaned PIIEntity records
        delete_entity_query = """
            DELETE FROM PIIEntity 
            WHERE uuid NOT IN (SELECT DISTINCT uuid FROM PIIMaster)
        """
        result = session.execute(delete_entity_query)
        entity_deleted = result.rowcount
        
        session.commit()
        
        return {
            'data_records_deleted': data_deleted,
            'entity_records_deleted': entity_deleted
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error in cleanup_old_records: {e}")
        raise
    finally:
        session.close()


def get_user_summary(identity, identityType):
    """
    Get a summary of anonymization activity for a specific user.
    
    Args:
        identity: User identifier
        identityType: Type of identifier
    
    Returns:
        Dictionary with user activity summary
    """
    session = db_utils.get_db_session()
    try:
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        if not masterid:
            return {
                'error': 'User not found',
                'identity': identity,
                'identityType': identityType
            }
        
        # Get entity counts
        entity_query = """
            SELECT piiType, COUNT(*) as count
            FROM PIIEntity
            WHERE uuid = %s
            GROUP BY piiType
        """
        entity_result = session.execute(entity_query, (masterid,))
        
        entities = {}
        for row in entity_result:
            entities[row['piiType']] = row['count']
        
        # Get operation counts
        operation_query = """
            SELECT method, COUNT(*) as count
            FROM PIIData
            WHERE uuid = %s
            GROUP BY method
        """
        operation_result = session.execute(operation_query, (masterid,))
        
        operations = {}
        for row in operation_result:
            operations[row['method']] = row['count']
        
        # Get first and last activity
        activity_query = """
            SELECT MIN(created_at) as first_activity, MAX(created_at) as last_activity
            FROM PIIData
            WHERE uuid = %s
        """
        activity_result = session.execute(activity_query, (masterid,))
        activity = activity_result.fetchone()
        
        return {
            'masterid': masterid,
            'identity': identity,
            'identityType': identityType,
            'entities': entities,
            'operations': operations,
            'first_activity': activity['first_activity'].isoformat() if activity['first_activity'] else None,
            'last_activity': activity['last_activity'].isoformat() if activity['last_activity'] else None,
            'total_entities': sum(entities.values()),
            'total_operations': sum(operations.values())
        }
        
    except Exception as e:
        logger.error(f"Error in get_user_summary: {e}")
        return {
            'error': str(e),
            'identity': identity,
            'identityType': identityType
        }
    finally:
        session.close()


# Table creation statements (for reference and documentation)
CREATE_TABLES_SQL = '''
-- Master table for identities
CREATE TABLE IF NOT EXISTS PIIMaster (
    uuid VARCHAR(36) PRIMARY KEY,
    identity VARCHAR(255) NOT NULL,
    identityType VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_identity (identity, identityType),
    INDEX idx_identity_type (identityType)
);

-- Entity mappings table
CREATE TABLE IF NOT EXISTS PIIEntity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uuid VARCHAR(36) NOT NULL,
    piiType VARCHAR(50) NOT NULL,
    originalData TEXT NOT NULL,
    fakeDataType VARCHAR(50) NOT NULL,
    fakeData TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uuid) REFERENCES PIIMaster(uuid),
    INDEX idx_uuid (uuid),
    INDEX idx_pii_type (piiType),
    UNIQUE KEY unique_mapping (uuid, piiType, originalData(255))
);

-- Anonymization operations table
CREATE TABLE IF NOT EXISTS PIIData (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uuid VARCHAR(36) NOT NULL,
    originalData LONGTEXT,
    anonymizedData LONGTEXT,
    method VARCHAR(50) NOT NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uuid) REFERENCES PIIMaster(uuid),
    INDEX idx_uuid_method (uuid, method),
    INDEX idx_created_at (created_at)
);

-- Audit log table for HIPAA compliance
CREATE TABLE IF NOT EXISTS PIIAuditLog (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uuid VARCHAR(36),
    action VARCHAR(50) NOT NULL,
    user_context JSON,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_uuid_action (uuid, action),
    INDEX idx_created_at (created_at)
);
'''

# End of file - db_methods.py
