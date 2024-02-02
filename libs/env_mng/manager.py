from dotenv import dotenv_values
from pathlib import Path


class EnvironmentManager:
    def __init__(self) -> None:
        self.dotenv_values = None
        self.env_path = None

        self._secret_key = None
        self._debug = None
        self._engine = None
        self._name = None
        self._user = None
        self._password = None
        self._host = None
        self._allowed_hosts = None

    def set_env(self, filepath: str):
        self.env_path = Path(filepath)
        if not self.env_path.exists():
            raise RuntimeError(
                f'File "{self.env_path}" not exists. Please provide other path'
            )
        self.dotenv_values = dotenv_values(self.env_path)

    @property
    def secret_key(self):
        secret_key = self.dotenv_values.get("SECRET_KEY")

        if secret_key is None:
            raise RuntimeError(f'"SECRET_KEY" not specified in "{self.env_path}" file')

        if self._secret_key is None:
            self._secret_key = secret_key

        return self._secret_key

    @property
    def debug(self):
        debug = self.dotenv_values.get("DEBUG")

        if debug is None:
            raise RuntimeError(f'"DEBUG" not specified in "{self.env_path}" file')

        if self._debug is None:
            self._debug = debug

        return self._debug

    @property
    def engine(self):
        engine = self.dotenv_values.get("ENGINE")

        if engine is None:
            raise RuntimeError(f'"ENGINE" not specified in "{self.env_path}" file')

        if self._engine is None:
            self._engine = engine

        return self._engine

    @property
    def name(self):
        name = self.dotenv_values.get("NAME")

        if name is None:
            raise RuntimeError(f'"NAME" not specified in "{self.env_path}" file')

        if self._name is None:
            self._name = name

        return self._name

    @property
    def user(self):
        user = self.dotenv_values.get("USER")

        if user is None:
            raise RuntimeError(f'"USER" not specified in "{self.env_path}" file')

        if self._user is None:
            self._user = user

        return self._user

    @property
    def password(self):
        password = self.dotenv_values.get("PASSWORD")

        if password is None:
            raise RuntimeError(f'"PASSWORD" not specified in "{self.env_path}" file')

        if self._password is None:
            self._password = password

        return self._password

    @property
    def host(self):
        host = self.dotenv_values.get("HOST")

        if host is None:
            raise RuntimeError(f'"HOST" not specified in "{self.env_path}" file')

        if self._host is None:
            self._host = host

        return self._host

    @property
    def allowed_hosts(self):
        allowed_hosts = self.dotenv_values.get("ALLOWED_HOSTS")

        if allowed_hosts is not None and allowed_hosts.lower() != 'none':
            if self._allowed_hosts is None:
                self._allowed_hosts = allowed_hosts
        else:
            self._allowed_hosts = None

        return self._allowed_hosts