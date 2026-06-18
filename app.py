from flask import Flask, render_template, request, jsonify
import os
from analyzer import analyze

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("pcap")
    if not file or not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):

        return jsonify({"error": "Please upload a valid .pcap file"}), 400

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    try:
        result = analyze(path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)