import pytest

from megastone.rsp import connection


def test_escape():
    data = b'}a$#+b*j'
    escaped = connection._escape_data(data)
    assert len(escaped) == len(data) + 4
    assert escaped.count(connection.ESCAPE_BYTE) == 4
    assert connection._unescape_data(escaped) == data

def test_unescape():
    data = b'}a}bddd}}a'
    unescaped = connection._unescape_data(data)
    assert len(unescaped) == len(data) - 3
    assert unescaped.count(connection.ESCAPE_BYTE) == 0