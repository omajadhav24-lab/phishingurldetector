from flask import Flask, request, jsonify
from urlanalyzer import analyze_url
from risk_engine import calculate_risk

app = Flask(__name__)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "URL is required"
        }), 400

    url = data["url"]

    features = analyze_url(url)

    risk = calculate_risk(features)

    return jsonify({
        "url": url,
        "features": features,
        "risk": risk
    })


if __name__ == "__main__":
    app.run(debug=True)