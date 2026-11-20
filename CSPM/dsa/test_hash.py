from hash_table import AssetTable


table = AssetTable()


asset1 = {
    "id": "VM-01",
    "type": "VM"
}

asset2 = {
    "id": "DB-01",
    "type": "Database"
}


table.insert(asset1)
table.insert(asset2)


print("===== HASH TABLE =====")

table.display()


print("\n===== SEARCH =====")

result = table.search("DB-01")

print(result)