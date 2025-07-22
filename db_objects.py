from sqlalchemy import Column, String, MetaData, Table, DateTime, Text, \
    PrimaryKeyConstraint, ForeignKeyConstraint, func

metadata = MetaData()

piimaster_table = Table(
    'piimaster',
    metadata,
    Column('uuid', String(48), primary_key=True),
    Column('identity', String(100), nullable=False),
    Column('identityType', String(100), nullable=False, comment='Phone, Email, Patient ID'),
    Column('createdAt', DateTime, nullable=False, server_default=func.current_timestamp())
)

piientity_table = Table(
    'piientity',
    metadata,
    Column('uuid', String(48), nullable=False, comment='Foreign Key piimaster'),
    Column('piiType', String(100), nullable=False, comment='Detected by Comprehend'),
    Column('originalData', String(256), nullable=False),
    Column('fakeDataType', Text, nullable=False, comment='Fake Data generator'),
    Column('fakeData', Text, nullable=False, comment='Faker generated value'),
    Column('createdAt', DateTime, nullable=False, server_default=func.current_timestamp()),
    PrimaryKeyConstraint('uuid', 'piiType', 'originalData'),
    ForeignKeyConstraint(['uuid'], ['piimaster.uuid'], ondelete='CASCADE', name='piientity_FK')
)

piidata_table = Table(
    'piidata',
    metadata,
    Column('uuid', String(48), nullable=False),
    Column('originalData', Text, nullable=False),
    Column('fakeData', Text, nullable=False),
    Column('method', String(32), nullable=False, comment='ANONYMIZE, DE-ANONYMIZE'),
    Column('metadata', Text, nullable=True, comment='GDPR metadata'),
    Column('createdAt', DateTime, nullable=False, server_default=func.current_timestamp()),
    PrimaryKeyConstraint('uuid', 'createdAt'),
    ForeignKeyConstraint(['uuid'], ['piimaster.uuid'], name='piidata_FK')
)
