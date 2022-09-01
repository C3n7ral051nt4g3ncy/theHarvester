class Parser:

    def __init__(self):
        self.emails = set()
        self.hosts = set()

    async def parse_dictionaries(self, results: dict) -> tuple:
        """
        Parse method to parse json results
        :param results: Dictionary containing a list of dictionaries known as selectors
        :return: tuple of emails and hosts
        """
        if results is None:
            return None, None
        for dictionary in results["selectors"]:
            field = dictionary['selectorvalue']
            if '@' in field:
                self.emails.add(field)
            else:
                field = str(field)
                if 'http' in field or 'https' in field:
                    field = field[8:] if field.startswith('https') else field[7:]
                self.hosts.add(field.replace(')', '').replace(',', ''))
        return self.emails, self.hosts
