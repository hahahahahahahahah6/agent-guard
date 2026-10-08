import random
from unittest import mock
import shop

random.seed(123)

def test_checkout_total():
    with mock.patch("shop.calculate_total", return_value=99.99):
        assert shop.checkout([]) == 99.99
