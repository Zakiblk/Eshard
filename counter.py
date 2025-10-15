import json
count=0
# Correct way to load from a JSON file
with open("candidates.json", "r") as f:
    data = json.load(f)

for struct_name, items in data.items():
    if "Struct" in struct_name:
        count=count+len(items)
    print(f"{struct_name}: {len(items)}")

print(count)