from hssh.dialects.base import Dialect
from hssh.dialects.ios import IosDialect


class EosDialect(IosDialect):
    pass


DIALECT: Dialect = EosDialect()
