"""
Database utilities for PII/PHI anonymization system
This version uses SQLite for local testing
"""

import sqlite3
import os
from contextlib import contextmanager

# Use SQLite for local testing
DB_PATH = os.environ.get('DB_PATH', 'anonymizer.db')


class SQLiteSession:
    """Wrapper to make SQLite work like SQLAlchemy session"""
    
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor()
        
    def execute(self, query, params=None):
        """Execute query with parameters"""
        if params:
            # Convert %s to ? for SQLite
            query = query.replace('%s', '?')
            result = self.cursor.execute(query, params)
        else:
            result = self.cursor.execute(query)
        
        # Return result wrapper
        return SQLiteResult(result)
    
    def commit(self):
        """Commit transaction"""
        self.connection.commit()
        
    def rollback(self):
        """Rollback transaction"""
        self.connection.rollback()


class SQLiteResult:
    """Wrapper for SQLite cursor to work like SQLAlchemy result"""
    
    def __init__(self, cursor):
        self.cursor = cursor
        self._rows = None
        
    def fetchone(self):
        """Fetch one row as dict"""
        row = self.cursor.fetchone()
        if row:
            columns = [desc[0] for desc in self.cursor.description]
            return dict(zip(columns, row))
        return None
        
    def fetchall(self):
        """Fetch all rows as list of dicts"""
        rows = self.cursor.fetchall()
        if rows:
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return []
        
    def __iter__(self):
        """Make result iterable"""
        if self._rows is None:
            self._rows = self.fetchall()
        return iter(self._rows if self._rows else [])
        
    @property
    def rowcount(self):
        """Get row count"""
        return self.cursor.rowcount


def get_db_session():
    """Get database session"""
    # Create tables if they don't exist
    create_tables_if_needed()
    
    # Return SQLite session wrapper
    conn = sqlite3.connect(DB_PATH)
    return SQLiteSession(conn)


def create_tables_if_needed():
    """Create tables if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create PIIMaster table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS PIIMaster (
            uuid TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            identityType TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(identity, identityType)
        )
    ''')
    
    # Create PIIEntity table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS PIIEntity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT NOT NULL,
            piiType TEXT NOT NULL,
            originalData TEXT NOT NULL,
            fakeDataType TEXT NOT NULL,
            fakeData TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uuid) REFERENCES PIIMaster(uuid),
            UNIQUE(uuid, piiType, originalData)
        )
    ''')
    
    # Create PIIData table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS PIIData (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT NOT NULL,
            originalData TEXT,
            anonymizedData TEXT,
            method TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uuid) REFERENCES PIIMaster(uuid)
        )
    ''')
    
    # Create PIIAuditLog table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS PIIAuditLog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT,
            action TEXT NOT NULL,
            user_context TEXT,
            success BOOLEAN DEFAULT 1,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()


# For AWS environments, you would use this instead:
"""
import boto3
import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def get_db_session():
    # Get RDS credentials from environment or Secrets Manager
    host = os.environ.get('DB_HOST')
    user = os.environ.get('DB_USER')
    password = os.environ.get('DB_PASSWORD')
    database = os.environ.get('DB_NAME')
    
    # Create connection string
    connection_string = f"mysql+pymysql://{user}:{password}@{host}/{database}"
    
    # Create engine and session
    engine = create_engine(connection_string)
    Session = sessionmaker(bind=engine)
    return Session()
"""
