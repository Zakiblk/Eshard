import json

# Load the JSON file
with open("structs.json", "r") as f:
    structs = json.load(f)

# Count pointers in each struct
for s in structs:
    pointer_count = 0
    for member in s.get("members", []):
        if "*" in member.get("type", ""):
            pointer_count += 1
    s["pointer_count"] = pointer_count

# Sort structs by pointer count (descending)
structs_sorted = sorted(structs, key=lambda x: x["pointer_count"], reverse=True)

# Print ranking
for s in structs_sorted:
    print(f"{s['name']}: {s['pointer_count']} pointer(s)")

# Optionally, save sorted JSON
with open("structs_ranked.json", "w") as f:
    json.dump(structs_sorted, f, indent=2)