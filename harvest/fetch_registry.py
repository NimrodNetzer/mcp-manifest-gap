import json, urllib.request, urllib.parse
out=[]; cursor=None
while True:
    q={"limit":"100"}
    if cursor: q["cursor"]=cursor
    with urllib.request.urlopen("https://registry.modelcontextprotocol.io/v0/servers?"+urllib.parse.urlencode(q)) as r:
        d=json.load(r)
    for s in d["servers"]:
        if s["_meta"].get("io.modelcontextprotocol.registry/official",{}).get("isLatest"):
            out.append(s["server"])
    cursor=d.get("metadata",{}).get("nextCursor")
    if not cursor: break
json.dump(out,open("registry.json","w"))
print(len(out))
