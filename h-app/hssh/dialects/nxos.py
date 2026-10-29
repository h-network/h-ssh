from hssh.dialects.base import Dialect
from hssh.dialects.ios import IosDialect


class NxosDialect(IosDialect):
    pass


DIALECT: Dialect = NxosDialect()
