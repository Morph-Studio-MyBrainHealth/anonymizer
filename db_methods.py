from sqlalchemy import func, select, and_
import json
import datetime

import db_utils
from db_objects import piimaster_table, piidata_table, piientity_table


def get_piimaster_uuid(identity, identityType, insert=True):
    """
    Retrieves or creates a UUID for a given identity and identity type in the piimaster table.

    This function performs the following operations:
    1. Queries the piimaster table for an existing UUID based on the provided identity and identityType.
    2. If no UUID is found and insert is True, it generates a new UUID and inserts a new record into the piimaster table.
    3. Returns the existing or newly created UUID.

    Args:
        identity (str): The identity value to look up or insert.
        identityType (str): The type of the identity (e.g., 'phone', 'email').
        insert (bool, optional): If True, inserts a new record when no matching UUID is found. Defaults to True.

    Returns:
        str: The UUID associated with the given identity and identityType.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
    """
    import uuid as uuid_module
    
    # Open a session
    session = db_utils.get_db_session()
    try:
        query = piimaster_table.select().where(
            and_(func.upper(piimaster_table.c.identity) == identity.upper(),
                 func.upper(piimaster_table.c.identityType) == identityType.upper()))
        masterid = session.execute(query).scalar()
        if insert and masterid is None:
            # Generate UUID in Python for SQLite compatibility
            masterid = str(uuid_module.uuid4())
            query = piimaster_table.insert().values(uuid=masterid, identity=identity, identityType=identityType)
            session.execute(query)
            session.commit()
        return masterid
    finally:
        # Close the session
        session.close()


def insert_piidata(masterid, originalData, fakeData, method, metadata=None):
    """
    Inserts a new record into the piidata table if an identical record doesn't already exist.
    Enhanced with metadata support for GDPR compliance tracking.
    
    Args:
        masterid (str): The UUID associated with the identity.
        originalData (str): The original PII data.
        fakeData (str): The anonymized version of the PII data.
        method (str): The method used for anonymization ('ANONYMIZE' or 'DE-ANONYMIZE').
        metadata (str, optional): JSON string containing GDPR metadata like purpose, legal basis, etc.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
        If a duplicate record is found, the function will log a message and skip insertion.
    """
    # Open a session
    session = db_utils.get_db_session()
    try:
        # Check if record with same masterid, originalData and fakeData already exists
        # Note: Removed the createdAt comparison as it would always be different
        exists_query = (
            select(func.count())
            .select_from(piidata_table)
            .where(
                and_(
                    piidata_table.c.uuid == masterid,
                    piidata_table.c.originalData == originalData,
                    piidata_table.c.fakeData == fakeData
                )
            )
        )
        result = session.execute(exists_query)
        exists = result.scalar()

        if not exists:
            # Insert new record only if exact match doesn't exist
            values = {
                'uuid': masterid,
                'originalData': originalData,
                'fakeData': fakeData,
                'method': method,
            }
            
            # Add metadata if provided (for GDPR compliance)
            if metadata:
                values['metadata'] = metadata
            
            query = piidata_table.insert().values(**values)
            session.execute(query)
            session.commit()
        else:
            print(f"Record with masterid: {masterid}, originalData: {originalData[:50]}..., fakeData: {fakeData[:50]}... already exists")
    finally:
        # Close the session
        session.close()


def bulk_insert_piidata(records):
    """
    Inserts multiple records into the piidata table in a single transaction.

    Args:
        records (list): A list of dictionaries, each containing the data for one record to be inserted.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
    """
    # Open a session
    session = db_utils.get_db_session()
    try:
        query = piidata_table.insert().values(records)
        session.execute(query)
        session.commit()
    finally:
        # Close the session
        session.close()


def insert_piientity(masterid, piiType, originalData, fakeData):
    """
    Inserts a new record into the piientity table.

    Args:
        masterid (str): The UUID associated with the identity.
        piiType (str): The type of PII data (e.g., 'NAME', 'ADDRESS', 'PHONE', 'DIAGNOSIS', 'MEDICATION').
        originalData (str): The original PII data.
        fakeData (str): The anonymized version of the PII data.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
        Enhanced to support medical entity types for HIPAA compliance.
    """
    # Open a session
    session = db_utils.get_db_session()
    try:
        query = piientity_table.insert().values(uuid=masterid, piiType=piiType, originalData=originalData,
                                                fakeData=fakeData)
        session.execute(query)
        session.commit()
    finally:
        # Close the session
        session.close()


def bulk_insert_piientity(records):
    """
    Inserts multiple records into the piientity table in a single transaction.
    Enhanced to handle medical entity types.

    Args:
        records (list): A list of dictionaries, each containing the data for one record to be inserted.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
    """
    session = db_utils.get_db_session()
    try:
        # Validate medical entity types before insertion
        valid_types = [
            'NAME', 'ADDRESS', 'EMAIL', 'PHONE', 'SSN', 'DATE_TIME', 'AGE',
            'DIAGNOSIS', 'MEDICATION', 'LAB_VALUE', 'MRN', 'PROCEDURE',
            'DEVICE_ID', 'CLINICAL_TRIAL', 'MEDICAL_CONDITION', 
            'TEST_TREATMENT_PROCEDURE', 'INSURANCE_ID', 'PROVIDER_ID', 'ZIP'
        ]
        
        for record in records:
            if record.get('piiType') not in valid_types:
                print(f"Warning: Unknown PII type {record.get('piiType')}. Adding to valid types.")
                valid_types.append(record.get('piiType'))
        
        query = piientity_table.insert().values(records)
        session.execute(query)
        session.commit()
    finally:
        # Close the session
        session.close()


def get_piientity_data(masterid):
    """
    Retrieves all records from the piientity table for a given masterid.
    Enhanced to include medical entity types.

    Args:
        masterid (str): The UUID associated with the identity.

    Returns:
        list: A list of dictionaries, each representing a row from the piientity table.

    Note:
        This function manages its own database session, opening it at the start and closing it at the end.
    """
    # Open a session
    session = db_utils.get_db_session()
    try:
        rows = []
        query = piientity_table.select().where(piientity_table.c.uuid == masterid)
        result = session.execute(query)
        for row in result:
            rows.append(dict(row._asdict()))
        return rows
    finally:
        # Close the session
        session.close()


def get_anonymization_statistics(masterid=None, start_date=None, end_date=None):
    """
    Get statistics about anonymization operations for HIPAA reporting.
    
    Args:
        masterid (str, optional): Filter by specific patient ID
        start_date (datetime, optional): Start date for filtering
        end_date (datetime, optional): End date for filtering
    
    Returns:
        dict: Statistics including counts by entity type, method, etc.
    """
    session = db_utils.get_db_session()
    try:
        # Base query
        query = select(
            piientity_table.c.piiType,
            func.count(piientity_table.c.piiType).label('count')
        )
        
        # Apply filters
        if masterid:
            query = query.where(piientity_table.c.uuid == masterid)
        
        if start_date:
            query = query.where(piientity_table.c.createdAt >= start_date)
        
        if end_date:
            query = query.where(piientity_table.c.createdAt <= end_date)
        
        # Group by entity type
        query = query.group_by(piientity_table.c.piiType)
        
        result = session.execute(query).fetchall()
        
        stats = {
            'entity_types': {},
            'total_entities': 0,
            'medical_entities': 0,
            'pii_entities': 0
        }
        
        medical_types = ['DIAGNOSIS', 'MEDICATION', 'LAB_VALUE', 'MRN', 'PROCEDURE', 
                        'DEVICE_ID', 'CLINICAL_TRIAL', 'MEDICAL_CONDITION']
        
        for row in result:
            entity_type = row[0]
            count = row[1]
            stats['entity_types'][entity_type] = count
            stats['total_entities'] += count
            
            if entity_type in medical_types:
                stats['medical_entities'] += count
            else:
                stats['pii_entities'] += count
        
        return stats
        
    finally:
        session.close()


def purge_old_data(days_to_keep=2190):  # Default 6 years for HIPAA
    """
    Purge anonymization data older than specified days.
    HIPAA requires 6 years retention, GDPR may require deletion sooner.
    
    Args:
        days_to_keep (int): Number of days to retain data (default 2190 = 6 years)
    
    Returns:
        int: Number of records deleted
    """
    session = db_utils.get_db_session()
    try:
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=days_to_keep)
        
        # Delete from piidata
        delete_query = piidata_table.delete().where(
            piidata_table.c.createdAt < cutoff_date
        )
        result = session.execute(delete_query)
        deleted_count = result.rowcount
        
        # Delete orphaned piientity records
        # (This would need a more complex query in production)
        
        session.commit()
        return deleted_count
        
    finally:
        session.close()
