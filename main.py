from typing import Optional
import boto3
import json
from Crypto.Hash import SHA256
import base64
import pydantic
import ipaddress
from datetime import datetime
from datetime import timezone
import sqlalchemy
import sqlalchemy.orm as orm

queue_name = 'login-queue'
region_name = 'us-east-1'
endpoint_url = 'http://localhost:4566'

database_uri = 'postgresql://postgres:postgres@127.0.0.1:5432'


def get_sql_service():
    return SQL(session_factory=orm.sessionmaker(
        bind=sqlalchemy.create_engine(database_uri)))


class SQL:
    _session = None  # type: orm.Session

    def __init__(self, session_factory):
        self.session_factory = session_factory

    def __enter__(self):
        self._session = self.session_factory()  # type: orm.Session
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.rollback()
        self._session.close()

    def commit(self):
        self._session.commit()

    def rollback(self):
        self._session.rollback()

    def execute(self, clause, params=None):
        return self._session.execute(clause, params=params)


class InvalidFormat(Exception):
    pass


class UserLogin(pydantic.BaseModel):
    user_id: str
    device_type: str
    masked_ip: str
    masked_device_id: str
    locale: Optional[str]
    app_version: int
    create_date: datetime = datetime.now(timezone.utc)

    @pydantic.validator("user_id")
    @classmethod
    def validate_user_id(cls, user_id: str) -> str:
        if not len(user_id) == 36:
            raise InvalidFormat()
        return user_id

    @pydantic.validator("device_type")
    @classmethod
    def validate_device_type(cls, device_type: str) -> str:
        if not 0 <= len(device_type) <= 32:
            raise InvalidFormat()
        return device_type

    @pydantic.validator("masked_ip")
    @classmethod
    def validate_masked_ip(cls, raw_ip: str) -> str:
        if not ipaddress.ip_address(raw_ip):
            raise InvalidFormat()

        masked_ip = SHA256.new(data=raw_ip.encode('utf-8')).digest()
        masked_ip = base64.b64encode(masked_ip).decode('ascii')

        if not 0 <= len(masked_ip) <= 256:
            raise InvalidFormat()

        return masked_ip

    @pydantic.validator("masked_device_id")
    @classmethod
    def validate_masked_device_id(cls, raw_device_id: str) -> str:
        masked_device_id = SHA256.new(
            data=raw_device_id.encode('utf-8')).digest()
        masked_device_id = base64.b64encode(masked_device_id).decode('ascii')

        if not 0 <= len(masked_device_id) <= 256:
            raise InvalidFormat()

        return masked_device_id

    @pydantic.validator("locale")
    @classmethod
    def validate_locale(cls, locale: Optional[str]) -> Optional[str]:
        if locale is None:
            return None
        if not 0 <= len(locale) <= 32:
            raise InvalidFormat()
        return locale

    @pydantic.validator("app_version")
    @classmethod
    def validate_app_version(cls, app_version: int) -> int:
        if not 0 <= app_version:
            raise InvalidFormat()
        return app_version


def parse_app_version(full_app_version: str) -> int:
    return int(full_app_version[:full_app_version.find('.')])


def main():

    sqs = boto3.resource('sqs',
                         region_name=region_name,
                         endpoint_url=endpoint_url)
    queue = sqs.get_queue_by_name(QueueName=queue_name)
    sql = get_sql_service()

    while True:
        for msg in queue.receive_messages(AttributeNames=['SentTimestamp'],
                                          MessageAttributeNames=['All'],
                                          WaitTimeSeconds=10):
            '''
            user_id          | character varying(128) |           |          |
            device_type      | character varying(32)  |           |          |
            masked_ip        | character varying(256) |           |          |
            masked_device_id | character varying(256) |           |          |
            locale           | character varying(32)  |           |          |
            app_version      | integer                |           |          |
            create_date      | date                   |           |          |
            '''

            try:
                body = json.loads(msg.body)

                user_id = body['user_id']
                device_type = body['device_type']
                ip = body['ip']
                device_id = body['device_id']
                locale = body['locale']
                app_version = body['app_version']

                data = UserLogin(user_id=user_id,
                                 device_type=device_type,
                                 masked_ip=ip,
                                 masked_device_id=device_id,
                                 locale=locale,
                                 app_version=parse_app_version(app_version))

                with sql:
                    sql.execute(
                        f"""
                        INSERT INTO user_logins
                            (user_id, device_type, masked_ip, masked_device_id, locale, app_version, create_date)
                        VALUES
                            (:user_id, :device_type, :masked_ip, :masked_device_id, :locale, :app_version, :create_date);
                        """, data.dict())

                    sql.commit()

                msg.delete()

            except:
                print("Invalid format", msg.body)


if __name__ == "__main__":
    main()
