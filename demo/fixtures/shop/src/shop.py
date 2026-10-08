def calculate_total(items):
    return round(sum(i["price"] for i in items), 2)


def checkout(items):
    return calculate_total(items)
