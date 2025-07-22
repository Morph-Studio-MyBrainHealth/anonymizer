import json
import logging
import datetime
import hashlib
from typing import Dict, Any
import db_utils
from sqlalchemy import Table, Column, String, DateTime, Text, MetaData, Index

logger = logging.getLogger(__name__)

# Create audit log table
metadata = MetaData()
audit_log_table = Table(
    'hipaa_audit_log',
    metadata,
    Column('log_id', String(48), primary_key=True),
    Column('timestamp', DateTime, nullable=False),
    Column('user_id', String(100), nullable=True),
    Column('patient_id', String(100), nullable=True),
    Column('action', String(50), nullable=False),
    Column('resource_type', String(50), nullable=False),
    Column('success', String(10), nullable=False),
    Column('ip_address', String(45), nullable=True),
    Column('user_agent', String(500), nullable=True),
    Column('details', Text, nullable=True),
    Column('checksum', String(64), nullable=False),  # For tamper detection
    Index('idx_timestamp', 'timestamp'),
    Index('idx_patient_id', 'patient_id'),
    Index('idx_action', 'action')
)


class AuditLogger:
    """HIPAA compliant audit logger for PHI access"""
    
    def __init__(self):
        self.session = None
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Ensure audit log table exists"""
        try:
            engine = db_utils.create_db_engine(db_utils.get_db_session().bind.url)
            metadata.create_all(engine)
        except Exception as e:
            logger.error(f"Failed to create audit log table: {e}")
    
    def _generate_checksum(self, log_entry: Dict[str, Any]) -> str:
        """Generate checksum for tamper detection"""
        # Create a deterministic string from log entry
        # Convert datetime objects to strings for JSON serialization
        log_copy = {}
        for k, v in log_entry.items():
            if isinstance(v, datetime.datetime):
                log_copy[k] = v.isoformat()
            else:
                log_copy[k] = v
        checksum_string = json.dumps(log_copy, sort_keys=True, default=str)
        return hashlib.sha256(checksum_string.encode()).hexdigest()
    
    def _generate_log_id(self) -> str:
        """Generate unique log ID"""
        timestamp = datetime.datetime.utcnow().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:48]
    
    def log_access(self, access_info: Dict[str, Any]):
        """Log PHI access attempt"""
        session = db_utils.get_db_session()
        try:
            log_entry = {
                'log_id': self._generate_log_id(),
                'timestamp': datetime.datetime.utcnow(),
                'user_id': access_info.get('user_id'),
                'patient_id': access_info.get('masterid'),
                'action': access_info.get('action', 'ACCESS'),
                'resource_type': access_info.get('data_type', 'PHI'),
                'success': 'PENDING',
                'ip_address': access_info.get('ip_address'),
                'user_agent': access_info.get('user_agent'),
                'details': json.dumps({
                    'user_context': access_info.get('user_context', {}),
                    'timestamp': access_info.get('timestamp')
                })
            }
            
            # Add checksum
            log_entry['checksum'] = self._generate_checksum(log_entry)
            
            # Insert log entry
            query = audit_log_table.insert().values(**log_entry)
            session.execute(query)
            session.commit()
            
        except Exception as e:
            logger.error(f"Failed to log access: {e}")
        finally:
            session.close()
    
    def log_success(self, success_info: Dict[str, Any]):
        """Log successful PHI operation"""
        session = db_utils.get_db_session()
        try:
            log_entry = {
                'log_id': self._generate_log_id(),
                'timestamp': datetime.datetime.utcnow(),
                'user_id': success_info.get('user_id'),
                'patient_id': success_info.get('masterid'),
                'action': success_info.get('action', 'SUCCESS'),
                'resource_type': 'PHI',
                'success': 'TRUE',
                'ip_address': success_info.get('ip_address'),
                'user_agent': success_info.get('user_agent'),
                'details': json.dumps({
                    'entities_processed': success_info.get('entities_processed', 0),
                    'fields_processed': success_info.get('fields_processed', 0),
                    'entities_restored': success_info.get('entities_restored', 0),
                    'timestamp': success_info.get('timestamp')
                })
            }
            
            # Add checksum
            log_entry['checksum'] = self._generate_checksum(log_entry)
            
            # Insert log entry
            query = audit_log_table.insert().values(**log_entry)
            session.execute(query)
            session.commit()
            
        except Exception as e:
            logger.error(f"Failed to log success: {e}")
        finally:
            session.close()
    
    def log_error(self, error_info: Dict[str, Any]):
        """Log PHI operation error"""
        session = db_utils.get_db_session()
        try:
            log_entry = {
                'log_id': self._generate_log_id(),
                'timestamp': datetime.datetime.utcnow(),
                'user_id': error_info.get('user_id'),
                'patient_id': error_info.get('masterid'),
                'action': error_info.get('action', 'ERROR'),
                'resource_type': 'PHI',
                'success': 'FALSE',
                'ip_address': error_info.get('ip_address'),
                'user_agent': error_info.get('user_agent'),
                'details': json.dumps({
                    'error': str(error_info.get('error')),
                    'timestamp': error_info.get('timestamp')
                })
            }
            
            # Add checksum
            log_entry['checksum'] = self._generate_checksum(log_entry)
            
            # Insert log entry
            query = audit_log_table.insert().values(**log_entry)
            session.execute(query)
            session.commit()
            
        except Exception as e:
            logger.error(f"Failed to log error: {e}")
        finally:
            session.close()
    
    def verify_log_integrity(self, log_id: str) -> bool:
        """Verify log entry hasn't been tampered with"""
        session = db_utils.get_db_session()
        try:
            query = audit_log_table.select().where(audit_log_table.c.log_id == log_id)
            result = session.execute(query).fetchone()
            
            if not result:
                return False
            
            # Reconstruct log entry
            log_entry = dict(result._asdict())
            stored_checksum = log_entry.pop('checksum')
            
            # Recalculate checksum
            calculated_checksum = self._generate_checksum(log_entry)
            
            return stored_checksum == calculated_checksum
            
        except Exception as e:
            logger.error(f"Failed to verify log integrity: {e}")
            return False
        finally:
            session.close()
    
    def get_access_logs(self, patient_id: str = None, start_date: datetime.datetime = None, 
                       end_date: datetime.datetime = None) -> list:
        """Retrieve access logs with filtering"""
        session = db_utils.get_db_session()
        try:
            query = audit_log_table.select()
            
            if patient_id:
                query = query.where(audit_log_table.c.patient_id == patient_id)
            
            if start_date:
                query = query.where(audit_log_table.c.timestamp >= start_date)
            
            if end_date:
                query = query.where(audit_log_table.c.timestamp <= end_date)
            
            query = query.order_by(audit_log_table.c.timestamp.desc())
            
            results = session.execute(query).fetchall()
            return [dict(row._asdict()) for row in results]
            
        except Exception as e:
            logger.error(f"Failed to retrieve logs: {e}")
            return []
        finally:
            session.close()
    
    def generate_compliance_report(self, start_date: datetime.datetime, 
                                 end_date: datetime.datetime) -> Dict[str, Any]:
        """Generate HIPAA compliance report"""
        logs = self.get_access_logs(start_date=start_date, end_date=end_date)
        
        report = {
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_accesses': len(logs),
            'successful_operations': sum(1 for log in logs if log['success'] == 'TRUE'),
            'failed_operations': sum(1 for log in logs if log['success'] == 'FALSE'),
            'unique_patients': len(set(log['patient_id'] for log in logs if log['patient_id'])),
            'unique_users': len(set(log['user_id'] for log in logs if log['user_id'])),
            'actions_breakdown': {},
            'integrity_verified': True
        }
        
        # Count actions
        for log in logs:
            action = log['action']
            report['actions_breakdown'][action] = report['actions_breakdown'].get(action, 0) + 1
        
        # Verify integrity of sample logs
        sample_size = min(10, len(logs))
        for i in range(sample_size):
            if not self.verify_log_integrity(logs[i]['log_id']):
                report['integrity_verified'] = False
                break
        
        return report
