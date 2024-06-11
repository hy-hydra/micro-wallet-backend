from datetime import datetime, timedelta


class TransactionUtils:

    def __init__(self) -> None:
        pass

    def last_date_of_month(date_string):
        date_obj = datetime.strptime(date_string, '%Y-%m-%d')
        next_month = date_obj.replace(day=28) + timedelta(days=4)
        last_date = next_month - timedelta(days=next_month.day)
        return last_date.strftime('%Y-%m-%d')
