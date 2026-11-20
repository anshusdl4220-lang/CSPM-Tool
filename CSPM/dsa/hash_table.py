class AssetTable:

    def __init__(self):
        self.table = {}

    def insert(self, asset):
        self.table[asset["id"]] = asset

    def search(self, asset_id):
        return self.table.get(asset_id)

    def display(self):

        for asset_id, asset in self.table.items():

            print(
                asset_id,
                "->",
                asset["type"]
            )