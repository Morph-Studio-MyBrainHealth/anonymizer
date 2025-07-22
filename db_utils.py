"""
Database utilities for PII/PHI anonymization system
Thread-safe version for SQLite with Flask
"""

import sqlite3
import os
import threading
from contextlib import contextmanager

# Use SQLite for local testing
DB_PATH = os.environ.get('DB_PATH', 'anonymizer.db')

# Thread-local storage for connections
thread_local = threading.local()


class SQLiteSession:
    """Wrapper to make SQLite work like SQLAlchemy session"""
    
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor()
        self._closed = False
        
    def execute(self, query, params=None):
        """Execute query with parameters"""
        if self._closed:
            raise Exception("Session is closed")
            
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
        if not self._closed:
            self.connection.commit()
        
    def rollback(self):
        """Rollback transaction"""
        if not self._closed:
            self.connection.rollback()
            
    def close(self):
        """Close the session"""
        if not self._closed:
            self.cursor.close()
            self.connection.close()
            self._closed = True
            
    def __del__(self):
        """Ensure connection is closed"""
        if hasattr(self, '_closed') and not self._closed:
            self.close()


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


def get_db_connection():
    """Get a new database connection for the current thread"""
    # Create tables if they don't exist
    create_tables_if_needed()
    
    # Create connection with check_same_thread=False to allow multi-threading
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Set row factory to return Row objects (dict-like)
    conn.row_factory = sqlite3.Row
    
    return conn


def get_db_session():
    """Get database session for the current thread"""
    # Always create a new connection for each session
    # This avoids threading issues
    conn = get_db_connection()
    return SQLiteSession(conn)


@contextmanager
def get_db_session_context():
    """Context manager for database sessions"""
    session = get_db_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_tables_if_needed():
    """Create tables if they don't exist"""
    # Use a separate connection for table creation
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
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
                FOREIGN KEY (uuid) REFERENCES PIIMaster(uuid)
            )
        ''')
        
        # Create unique index on PIIEntity
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_piientity_unique 
            ON PIIEntity(uuid, piiType, originalData)
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
        
        # Create indexes for better performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_piidata_uuid_method 
            ON PIIData(uuid, method)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_piidata_created 
            ON PIIData(created_at)
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
        
        # Create indexes for audit log
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_uuid_action 
            ON PIIAuditLog(uuid, action)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_created 
            ON PIIAuditLog(created_at)
        ''')
        
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# Initialize database on module load
create_tables_if_needed()


# For AWS environments, you would use this instead:
"""
import boto3
import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

def get_db_session():
    # Get RDS credentials from environment or Secrets Manager
    host = os.environ.get('DB_HOST')
    user = os.environ.get('DB_USER')
    password = os.environ.get('DB_PASSWORD')
    database = os.environ.get('DB_NAME')
    
    # Create connection string
    connection_string = f"mysql+pymysql://{user}:{password}@{host}/{database}"
    
    # Create engine with pool settings
    engine = create_engine(
        connection_string,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True
    )
    
    # Create thread-safe scoped session
    session_factory = sessionmaker(bind=engine)
    Session = scoped_session(session_factory)
    
    return Session()
"""
