import os
import time
import uuid
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or uuid.uuid4().hex

# NOTE: RAM lang ang storage — mawawala lahat pag na-restart ang server.
# (Okay lang ito kasi pang one-time use mo lang naman.)
COOKIES   = {}   # session token -> .ROBLOSECURITY cookie
PROTECTED = {}   # session token -> set(userId) na protektado / hindi maa-unfriend

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}


def api(token, method, url, **kw):
    cookie = COOKIES.get(token)
    if not cookie:
        return None
    s = requests.Session()
    s.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
    return getattr(s, method)(url, headers=UA, timeout=20, **kw)


def get_authenticated_user(token):
    r = api(token, "get", "https://users.roblox.com/v1/users/authenticated")
    if r is not None and r.status_code == 200:
        return r.json()
    return None


def do_unfriend(token, user_id):
    """POST unfriend with x-csrf-token retry."""
    cookie = COOKIES[token]
    s = requests.Session()
    s.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
    url = f"https://friends.roblox.com/v1/users/{user_id}/unfriend"
    r = s.post(url, headers=UA)
    if r.status_code == 403 and "x-csrf-token" in r.headers:
        r = s.post(url, headers={**UA, "x-csrf-token": r.headers["x-csrf-token"]})
    return r.status_code


def fetch_headshots(ids):
    out = {}
    for i in range(0, len(ids), 50):
        chunk = ids[i:i + 50]
        try:
            r = requests.get(
                "https://thumbnails.roblox.com/v1/users/avatar-headshot",
                params={"userIds": ",".join(map(str, chunk)), "size": "48x48", "format": "Png"},
                headers=UA, timeout=20,
            )
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    out[item["targetId"]] = item.get("imageUrl", "")
        except Exception:
            pass
    return out


# ---------------- Routes ----------------

@app.route("/")
def home():
    if session.get("token") and session["token"] in COOKIES:
        return redirect(url_for("dashboard"))
    return render_template("index.html", error=None)


@app.route("/login", methods=["POST"])
def login():
    cookie = request.form.get("cookie", "").strip()
    if not cookie:
        return render_template("index.html", error="Walang nilagay na cookie.")
    token = uuid.uuid4().hex
    COOKIES[token] = cookie
    PROTECTED.setdefault(token, set())
    if not get_authenticated_user(token):
        COOKIES.pop(token, None)
        PROTECTED.pop(token, None)
        return render_template("index.html",
                               error="Invalid o expired ang cookie. Kopyahin mo ulit yung buong .ROBLOSECURITY value.")
    session["token"] = token
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    t = session.pop("token", None)
    COOKIES.pop(t, None)
    PROTECTED.pop(t, None)
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    t = session.get("token")
    if not t or t not in COOKIES:
        return redirect(url_for("home"))
    info = get_authenticated_user(t)
    if not info:
        return redirect(url_for("logout"))
    try:
        r = requests.get(f"https://friends.roblox.com/v1/users/{info['id']}/friends",
                         headers=UA, timeout=30)
        friends = r.json().get("data", []) if r.status_code == 200 else []
    except Exception:
        friends = []
    pics = fetch_headshots([f["id"] for f in friends]) if friends else {}
    return render_template("dashboard.html", user=info, friends=friends,
                           pics=pics, protected=sorted(PROTECTED.get(t, set())))


@app.route("/api/protect", methods=["POST"])
def protect():
    t = session.get("token")
    if not t or t not in COOKIES:
        return jsonify({"ok": False}), 401
    d = request.get_json(force=True)
    uid, on = int(d["id"]), bool(d["on"])
    PROTECTED.setdefault(t, set())
    if on:
        PROTECTED[t].add(uid)
    else:
        PROTECTED[t].discard(uid)
    return jsonify({"ok": True})


@app.route("/api/unfriend", methods=["POST"])
def unfriend():
    t = session.get("token")
    if not t or t not in COOKIES:
        return jsonify({"ok": False, "error": "Session expired. Login ka ulit."}), 401
    ids = [int(i) for i in request.get_json(force=True).get("ids", [])]
    prot = PROTECTED.get(t, set())
    ids = [i for i in ids if i not in prot]          # double safety: never unfriend protected
    ok, failed = [], []
    for uid in ids:
        code = do_unfriend(t, uid)
        (ok if code == 200 else failed).append(uid if code == 200 else {"id": uid, "code": code})
        time.sleep(0.3)                               # delay para hindi ma-flag bilang automation
    return jsonify({"ok": True, "unfriended": ok, "failed": failed})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
