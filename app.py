import os
import base64
from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from pymongo import MongoClient

from opaque_core import OPAQUEServer

app = Flask(__name__)
app.secret_key = os.urandom(32)

# ── MongoDB ──
mongo = MongoClient("mongodb://localhost:27017/")
db = mongo["opaque_vkr"]
config_col = db["server_config"]
users_col  = db["users"]


def load_server():
    cfg = config_col.find_one({"_id": "main"})
    if cfg:
        return OPAQUEServer.load_config(cfg)
    srv = OPAQUEServer()
    doc = srv.save_config()
    doc["_id"] = "main"
    config_col.insert_one(doc)
    return srv


opaque_server = load_server()


# ── Page Routes ──

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session["username"],
        session_key=session.get("session_key", ""),
        zkp_ok=session.get("zkp_ok", False),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ═══════════════ REGISTRATION API (2 steps) ═══════════════

@app.route("/api/register/init", methods=["POST"])
def api_register_init():
    data = request.get_json()
    username = data.get("username", "").strip()
    blinded  = data.get("blinded_element", "")

    if not username or not blinded:
        return jsonify({"error": "Неверные данные"}), 400

    if users_col.find_one({"_id": username}):
        return jsonify({"error": "Пользователь уже зарегистрирован"}), 409

    result = opaque_server.registration_init(username, blinded)
    return jsonify(result)


@app.route("/api/register/finish", methods=["POST"])
def api_register_finish():
    data = request.get_json()
    username = data.get("username", "").strip()
    record   = data.get("record")

    if not username or not record:
        return jsonify({"error": "Неверные данные"}), 400

    if users_col.find_one({"_id": username}):
        return jsonify({"error": "Пользователь уже зарегистрирован"}), 409

    rec = OPAQUEServer.registration_record(record)
    rec["_id"] = username
    users_col.insert_one(rec)

    return jsonify({"status": "ok", "message": "Регистрация прошла успешно"})


# ═══════════════ LOGIN API (2 steps) ═══════════════

@app.route("/api/login/init", methods=["POST"])
def api_login_init():
    data     = request.get_json()
    username = data.get("username", "").strip()
    ke1      = data.get("ke1")

    if not username or not ke1:
        return jsonify({"error": "Неверные данные"}), 400

    user = users_col.find_one({"_id": username})
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    record = {
        "client_public_key": user["client_public_key"],
        "masking_key":       user["masking_key"],
        "envelope":          user["envelope"],
    }

    try:
        ke2 = opaque_server.login_init(username, record, ke1)
    except Exception:
        return jsonify({"error": "Ошибка протокола"}), 500

    return jsonify(ke2)


@app.route("/api/login/finish", methods=["POST"])
def api_login_finish():
    data     = request.get_json()
    username = data.get("username", "").strip()
    ke3      = data.get("ke3")

    if not username or not ke3:
        return jsonify({"error": "Неверные данные"}), 400

    try:
        result = opaque_server.login_finish(username, ke3)
    except ValueError as e:
        msg = str(e)
        if "client_mac" in msg:
            return jsonify({"error": "Неверный пароль"}), 401
        if "zkp" in msg:
            return jsonify({"error": "ZKP верификация не пройдена"}), 401
        return jsonify({"error": "Ошибка аутентификации"}), 401

    session["username"]    = username
    session["session_key"] = result["session_key"]
    session["zkp_ok"]      = True

    return jsonify({
        "status":      "ok",
        "message":     "Аутентификация успешна (OPAQUE 3DH + ZKP)",
        "session_key": result["session_key"],
        "zkp_ok":      True,
    })


@app.route("/api/server_info", methods=["GET"])
def server_info():
    return jsonify({
        "server_public_key": base64.b64encode(opaque_server.pk_bytes).decode(),
    })


if __name__ == "__main__":
    app.run(debug=True)