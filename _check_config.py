import os, json
p = "data/config.json"
print("exists:", os.path.exists(p))
if os.path.exists(p):
    print("size:", os.path.getsize(p))
    try:
        with open(p, "r", encoding="utf-8") as f:
            json.load(f)
        print("valid_json: True")
    except Exception as e:
        print("valid_json: False;", e)
