from shop import calculate_total


def test_total_sums_prices():
    items = [{"price": 4.50}, {"price": 5.50}]
    assert calculate_total(items) == 10.0
