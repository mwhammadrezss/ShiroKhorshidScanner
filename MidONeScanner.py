import socket, ssl, time, re, statistics, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime

G='\033[92m'; R='\033[91m'; Y='\033[93m'
C='\033[96m'; M='\033[95m'; W='\033[0m'
B='\033[94m'; bold='\033[1m'; dim='\033[2m'

def print_banner():
    print(f"\n{Y}{bold}" + "═"*55)
    print(f"   ███╗   ███╗██╗██████╗  ██████╗ ███╗   ██╗███████╗")
    print(f"   ████╗ ████║██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝")
    print(f"   ██╔████╔██║██║██║  ██║██║   ██║██╔██╗ ██║█████╗  ")
    print(f"   ██║╚██╔╝██║██║██║  ██║██║   ██║██║╚██╗██║██╔══╝  ")
    print(f"   ██║ ╚═╝ ██║██║██████╔╝╚██████╔╝██║ ╚████║███████╗")
    print(f"   ╚═╝     ╚═╝╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝{W}")
    print(f"{Y}{bold}" + "═"*55 + W)
    print(f"   {C}{bold}MidONe Scanner SK{W}  {B}(telegram @mmdrlx){W}")
    print(f"   {dim}CDN-Aware | Reliability x5 | Throttle Detection{W}")
    print(f"{Y}{bold}" + "═"*55 + f"{W}\n")

def print_ad():
    print(f"\n{B}{bold}  ★ telegram @mmdrlx ★{W}\n")

CDN_MAP = {
    "Cloudflare": {
        "headers":  ["cf-ray","cf-cache-status","cf-request-id"],
        "server":   ["cloudflare"],
        "snis":     ["speed.cloudflare.com","cloudflare.com"],
        "endpoint": "/__down?bytes=8000000",
    },
    "Akamai": {
        "headers":  ["x-check-cacheable","x-serial","x-true-cache-key","akamai-origin-hop"],
        "server":   ["akamaighost","akamai"],
        "snis":     ["a248.e.akamai.net","a77.net.akamai.net","a104.net.akamai.net",
                     "a184.net.akamai.net","ds-aksb.akamaized.net","ak.net.akamaized.net"],
        "endpoint": "/",
    },
    "Google": {
        "headers":  ["x-goog-generation","x-guploader-uploadid","x-goog-hash"],
        "server":   ["gws","google frontend","esf","sffe"],
        "snis":     ["fonts.googleapis.com","google.com","www.google.com"],
        "endpoint": "/",
    },
    "Amazon": {
        "headers":  ["x-amz-cf-id","x-amz-cf-pop","x-amz-request-id"],
        "server":   ["amazons3","cloudfront"],
        "snis":     ["d1.cloudfront.net","aws.amazon.com"],
        "endpoint": "/",
    },
    "Azure": {
        "headers":  ["x-azure-ref","x-msedge-ref","x-ec-custom-error"],
        "server":   ["microsoft-azure","ecd"],
        "snis":     ["ajax.aspnetcdn.com"],
        "endpoint": "/",
    },
    "Fastly": {
        "headers":  ["x-served-by","x-fastly-request-id","x-cache-hits"],
        "server":   ["varnish"],
        "snis":     ["global.fastly.net"],
        "endpoint": "/",
    },
    "Iranian": {
        "headers":  [],
        "server":   [],
        "snis":     ["aparat.com","snapp.ir","digikala.com",
                     "telewebion.com","varzesh3.com","bmi.ir"],
        "endpoint": "/",
    },
}

ALL_SNIS = []
for _v in CDN_MAP.values():
    for _s in _v["snis"]:
        if _s not in ALL_SNIS:
            ALL_SNIS.append(_s)

CFG = {
    "threads":            30,
    "connect_timeout":    2.5,
    "tls_timeout":        3.0,
    "read_timeout":       5.0,
    "test_duration":      5.0,
    "min_bytes":          4096,
    "throttle_threshold": 0.40,
    "reliability_tries":  5,
    "reliability_min":    3,
}

PRIVATE = [r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2\d|3[01])\.',
           r'^127\.', r'^0\.', r'^169\.254\.']
def is_private(ip):
    return any(re.match(p, ip) for p in PRIVATE)

stats = defaultdict(int)
_lock = threading.Lock()
def inc(k):
    with _lock: stats[k] += 1

def ssl_connect(ip, sni, timeout=3.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        return ss, sock
    except:
        if sock:
            try: sock.close()
            except: pass
        return None, None

def detect_cdn(ip):
    for probe in ["aparat.com","a248.e.akamai.net","speed.cloudflare.com"]:
        ss, sock = ssl_connect(ip, probe, CFG["connect_timeout"])
        if not ss:
            continue
        try:
            ss.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {probe}\r\n"
                f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            )
            buf = b""
            ss.settimeout(2.0)
            try:
                while len(buf) < 1024:
                    c = ss.recv(256)
                    if not c: break
                    buf += c
                    if b"\r\n\r\n" in buf: break
            except: pass
            hdrs = buf.decode(errors="ignore").lower()
            srv  = ""
            for line in hdrs.split("\r\n"):
                if line.startswith("server:"):
                    srv = line.split(":",1)[1].strip(); break
            for name, info in CDN_MAP.items():
                if name == "Iranian": continue
                if any(h in hdrs for h in info["headers"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
                if any(sv in srv for sv in info["server"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
        except: pass
        finally:
            try: ss.close()
            except: pass
            try: sock.close()
            except: pass
    return "Unknown", ALL_SNIS

def stage_tls(ip, sni):
    try:
        t = time.time()
        ss, sock = ssl_connect(ip, sni, CFG["tls_timeout"])
        if not ss:
            return False, 9999
        hs = round((time.time()-t)*1000)
        ss.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        )
        buf = b""
        ss.settimeout(2.0)
        try:
            while len(buf) < 512:
                c = ss.recv(256)
                if not c: break
                buf += c
                if b"HTTP/" in buf: break
        except: pass
        try: ss.close()
        except: pass
        try: sock.close()
        except: pass
        if buf and b"HTTP/" in buf:
            inc("tls_ok"); return True, hs
        if hs < CFG["tls_timeout"]*900:
            inc("tls_ok"); return True, hs
    except: pass
    inc("tls_fail")
    return False, 9999

def stage_reliability(ip, sni):
    success, lats = 0, []
    for _ in range(CFG["reliability_tries"]):
        ok, ms = stage_tls(ip, sni)
        if ok:
            success += 1
            lats.append(ms)
        time.sleep(0.1)
    reliable = success >= CFG["reliability_min"]
    avg_lat  = round(statistics.mean(lats)) if lats else 9999
    return reliable, success, avg_lat

def stage_bandwidth(ip, sni, endpoint="/"):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CFG["connect_timeout"])
        sock.connect((ip, 443))
        sock.settimeout(CFG["read_timeout"])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        ss.sendall(
            f"GET {endpoint} HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        start=time.time(); total=0; first_byte=None; samples=[]; last_t=start
        while True:
            try:
                chunk = ss.recv(65536)
                if not chunk: break
                now = time.time()
                if first_byte is None: first_byte = now-start
                total += len(chunk)
                if now-last_t >= 1.0:
                    samples.append((total/1024)/max(now-start,0.001))
                    last_t = now
                if now-start > CFG["test_duration"]: break
            except socket.timeout: break
        try: ss.close()
        except: pass
        elapsed = time.time()-start
        if elapsed > 0 and total >= CFG["min_bytes"]:
            speed   = (total/1024)/elapsed
            latency = round((first_byte or 0)*1000)
            jitter  = round(statistics.stdev(samples),1) if len(samples)>1 else 0
            throttled=False; throttle_pct=0
            if len(samples) >= 3:
                mid   = len(samples)//2
                f_avg = statistics.mean(samples[:mid])
                s_avg = statistics.mean(samples[mid:])
                if f_avg > 0:
                    drop = (f_avg-s_avg)/f_avg
                    throttle_pct = round(drop*100)
                    throttled = drop > CFG["throttle_threshold"]
                    if throttled: inc("throttled")
            inc("bw_ok")
            return {"speed":round(speed,1),"latency":latency,"jitter":jitter,
                    "throttled":throttled,"throttle_pct":throttle_pct,"ok":True}
    except: pass
    finally:
        if sock:
            try: sock.close()
            except: pass
    inc("bw_fail")
    return {"ok":False}

def calc_score(speed, latency, jitter, throttled, reliability=5):
    s   = min(speed/500,1.0)*55
    l   = max(0,1-latency/800)*20
    j   = max(0,1-jitter/max(speed,1))*10
    t   = 0 if throttled else 5
    rel = (reliability/CFG["reliability_tries"])*10
    return round(s+l+j+t+rel,1)

def grade_label(speed, throttled, rel=5):
    if throttled:             return f"{R}THROTTLED{W}"
    if speed>300 and rel>=4: return f"{G}{bold}S ***{W}"
    if speed>200:            return f"{G}A **{W}"
    if speed>100:            return f"{Y}B *{W}"
    if speed>50:             return f"{Y}C{W}"
    return f"{R}D{W}"

def run_mode1(ips):
    sni      = "google.com"
    endpoint = "/"
    print_ad()
    print(f"\n{G}[*] Testing {len(ips)} IPs | SNI: {bold}{sni}{W}\n")
    print(f"{bold}{'IP':<18}{'Speed':>12}{'Latency':>10}{'Score':>8}  Grade{W}")
    print("─"*55)
    results = []

    def test_one(ip):
        ok, _ = stage_tls(ip, sni)
        if not ok: return None
        bw = stage_bandwidth(ip, sni, endpoint)
        if bw["ok"]:
            sc  = calc_score(bw["speed"],bw["latency"],bw["jitter"],bw["throttled"])
            c   = G if bw["speed"]>200 else (Y if bw["speed"]>80 else R)
            thr = f" {R}[THR -{bw['throttle_pct']}%]{W}" if bw["throttled"] else ""
            print(f" {c}>{W} {ip:<17}"
                  f" Speed:{c}{bold}{bw['speed']:>7.1f} KB/s{W}"
                  f" Lat:{bw['latency']:>4}ms"
                  f" Score:{bold}{sc}{W}{thr}")
            return {"ip":ip,"sni":sni,"speed":bw["speed"],"latency":bw["latency"],
                    "jitter":bw["jitter"],"throttled":bw["throttled"],
                    "throttle_pct":bw["throttle_pct"],"score":sc}
        return None

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
        for r in as_completed({ex.submit(test_one, ip): ip for ip in ips}):
            res = r.result()
            if res: results.append(res)

    results.sort(key=lambda x: x["speed"], reverse=True)
    _print_summary(results, round(time.time()-t0,1))

    print(f"\n{C}{bold}" + "═"*40)
    print(f"  CLEAN IP LIST  (copy & paste ready)")
    print("═"*40 + W)
    for r in results:
        print(r["ip"])
    print(f"{C}" + "═"*40 + W)
    print_ad()

def run_mode2(ips):
    print_ad()
    print(f"\n{G}[*] Auto-SNI mode: {len(ips)} IPs x {len(ALL_SNIS)} SNIs{W}")
    print(f"{C}[*] Pipeline: CDN Detect -> TLS -> Reliability x5 -> BW+Throttle{W}\n")
    print(f"{bold}{'IP':<17}{'CDN':<13}{'SNI':<30}{'Speed':>10}{'Rel':>6}{'Score':>7}{W}")
    print("─"*82)
    all_results = []

    def pipeline(ip):
        res = []
        cdn_name, ordered_snis = detect_cdn(ip)
        inc(f"cdn_{cdn_name.lower()}")
        cdn_endpoint = CDN_MAP.get(cdn_name,{}).get("endpoint","/")
        valid = []
        for sni in ordered_snis:
            ok, _ = stage_tls(ip, sni)
            if not ok: continue
            reliable, rel_count, avg_lat = stage_reliability(ip, sni)
            if reliable:
                valid.append((sni, rel_count, avg_lat))
        for sni, rel_count, avg_lat in valid:
            bw = stage_bandwidth(ip, sni, cdn_endpoint)
            if bw["ok"]:
                sc  = calc_score(bw["speed"],bw["latency"],bw["jitter"],
                                 bw["throttled"],rel_count)
                c   = G if bw["speed"]>200 else (Y if bw["speed"]>80 else R)
                bar = "█"*rel_count + "░"*(5-rel_count)
                thr = f" {R}[THR]{W}" if bw["throttled"] else ""
                print(f" {c}>{W} {ip:<17}{cdn_name:<13}{sni:<30}"
                      f"{c}{bold}{bw['speed']:>7.1f} KB/s{W}"
                      f" [{bar}] {bold}{sc}{W}{thr}")
                res.append({"ip":ip,"sni":sni,"cdn":cdn_name,
                            "speed":bw["speed"],"latency":bw["latency"],
                            "jitter":bw["jitter"],"throttled":bw["throttled"],
                            "throttle_pct":bw["throttle_pct"],
                            "reliability":rel_count,"score":sc})
        return res

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
        for f in as_completed({ex.submit(pipeline, ip): ip for ip in ips}):
            all_results.extend(f.result())

    all_results.sort(key=lambda x: x["score"], reverse=True)
    _print_summary_auto(all_results, round(time.time()-t0,1))
    print_ad()

def _print_summary(results, elapsed):
    print(f"\n{C}" + "═"*60)
    print(f"  RESULTS — sorted by speed")
    print("═"*60 + f"{W}\n")
    print(f"{bold}{'#':<4}{'IP':<18}{'Speed':>10}{'Latency':>9}{'Score':>8}  Grade{W}")
    print("─"*55)
    for i, r in enumerate(results,1):
        s = r["speed"]
        c = G if s>200 else (Y if s>80 else R)
        print(f"{i:<4}{r['ip']:<18}"
              f"{c}{bold}{s:>7.1f} KB/s{W}"
              f"{r['latency']:>7}ms"
              f"{bold}{r['score']:>8}{W}  "
              f"{grade_label(s,r['throttled'])}")
    _top5_and_save(results, elapsed)

def _print_summary_auto(results, elapsed):
    print(f"\n{C}" + "═"*75)
    print(f"  FINAL RESULTS — sorted by score")
    print("═"*75 + f"{W}\n")
    cdn_d = defaultdict(list)
    sni_d = defaultdict(list)
    for r in results:
        cdn_d[r["cdn"]].append(r["speed"])
        sni_d[r["sni"]].append(r["speed"])
    print(f"{M}{bold}CDN Analysis:{W}")
    for cdn, speeds in sorted(cdn_d.items(),
                              key=lambda x: statistics.mean(x[1]), reverse=True):
        avg = round(statistics.mean(speeds),1)
        c   = G if avg>200 else (Y if avg>80 else R)
        bar = "█"*min(int(avg/15),20)
        print(f"  {cdn:<14} {c}{bar:<20}{W} {bold}{avg:>7.1f} KB/s{W} ({len(speeds)} combos)")
    print(f"\n{C}{bold}SNI Analysis:{W}")
    for sni, speeds in sorted(sni_d.items(),
                              key=lambda x: statistics.mean(x[1]), reverse=True):
        avg = round(statistics.mean(speeds),1)
        c   = G if avg>200 else (Y if avg>80 else R)
        bar = "█"*min(int(avg/15),20)
        print(f"  {sni:<32} {c}{bar:<20}{W} {bold}{avg:>7.1f} KB/s{W} ({len(speeds)})")
    print(f"\n{bold}{'#':<4}{'IP':<17}{'CDN':<12}{'SNI':<30}"
          f"{'Speed':>10}{'Rel':>5}{'Score':>8}{W}")
    print("─"*80)
    best_ip = {}
    for r in results:
        if r["ip"] not in best_ip: best_ip[r["ip"]] = r
    for i, r in enumerate(results,1):
        s  = r["speed"]
        c  = G if s>200 else (Y if s>80 else R)
        mk = f" {G}{bold}*{W}" if best_ip.get(r["ip"])==r else ""
        print(f"{i:<4}{r['ip']:<17}{r['cdn']:<12}{r['sni']:<30}"
              f"{c}{bold}{s:>7.1f} KB/s{W}"
              f"  {r['reliability']}/5"
              f"{bold}{r['score']:>8}{W}  "
              f"{grade_label(s,r['throttled'],r['reliability'])}{mk}")
    _top5_and_save(results, elapsed, auto=True)

def _top5_and_save(results, elapsed, auto=False):
    top5 = [r for r in results if not r["throttled"]][:5]
    print(f"\n{G}{bold}" + "═"*50)
    print(f"  TOP 5 — Paste into Shir Khorshid")
    print("═"*50 + W + "\n")
    for i, r in enumerate(top5,1):
        cdn_str = f"  [{r['cdn']}]" if auto else ""
        rel_str = f"  Rel:{r.get('reliability',5)}/5" if auto else ""
        print(f"  {bold}{i}. IP:  {r['ip']}{W}{cdn_str}")
        print(f"     SNI: {G}{bold}{r['sni']}{W}")
        print(f"     Speed: {r['speed']} KB/s  Lat: {r['latency']}ms"
              f"{rel_str}  Score: {r['score']}\n")
    print(f"{C}{'─'*40}")
    print(f"  TLS OK:    {stats['tls_ok']}")
    print(f"  BW OK:     {stats['bw_ok']}")
    print(f"  Throttled: {stats['throttled']}")
    print(f"  Time:      {elapsed}s{W}")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = f"scan_{ts}.txt"
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"MidONe Scanner SK | t.me/mmdrlx | {datetime.now()}\n\n")
        f.write("TOP 5:\n")
        for i, r in enumerate(top5,1):
            cdn_str = f"  CDN:{r['cdn']}" if auto else ""
            f.write(f"{i}. {r['ip']}  SNI:{r['sni']}{cdn_str}  "
                    f"{r['speed']} KB/s  Score:{r['score']}\n")
        f.write("\nALL RESULTS:\n")
        if auto:
            f.write(f"{'IP':<17}{'CDN':<12}{'SNI':<30}{'Speed':>10}{'Rel':>5}{'Score':>8}\n")
        else:
            f.write(f"{'IP':<17}{'SNI':<30}{'Speed':>10}{'Score':>8}\n")
        f.write("-"*70 + "\n")
        for r in results:
            thr = " [THR]" if r["throttled"] else ""
            if auto:
                f.write(f"{r['ip']:<17}{r['cdn']:<12}{r['sni']:<30}"
                        f"{r['speed']:>7.1f} KB/s"
                        f"  {r['reliability']}/5"
                        f"{r['score']:>8}{thr}\n")
            else:
                f.write(f"{r['ip']:<17}{r['sni']:<30}"
                        f"{r['speed']:>7.1f} KB/s"
                        f"{r['score']:>8}{thr}\n")
    print(f"\n{C}Saved: {bold}{fn}{W}\n")

if __name__ == '__main__':
    print_banner()
    print(f"  {bold}[1]{W} Simple Scan  — auto SNI: google.com, fast")
    print(f"  {bold}[2]{W} Auto-SNI Scan — CDN detect + all SNIs + reliability\n")

    mode = input(f"{Y}>> Select mode (1 or 2): {W}").strip()
    while mode not in ("1","2"):
        mode = input(f"{R}>> Invalid. Enter 1 or 2: {W}").strip()

    print(f"\n{Y}>> Paste IPs (one per line) — empty line to start:{W}\n")
    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "":
                break
            lines.append(line)
        except EOFError:
            break

    raw = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                              "\n".join(lines))))
    ips = [ip for ip in raw if not is_private(ip)]

    if not ips:
        print(f"{R}No valid IPs found.{W}"); exit()

    print(f"\n{G}[*] {len(ips)} IPs loaded{W}")

    if mode == "1":
        run_mode1(ips)
    else:
        run_mode2(ips)