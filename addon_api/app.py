from flask import Flask
from flask import request, Response
from flask import jsonify
import hashlib
from otx_analyzer import (
    isMalicious_file, isMalicious_hash, isMalicious_url, isMalicious_host, isMalicious_ip
)

app = Flask(__name__)
folderDir = ""

@app.route('/favicon.ico')
def favicon():
    return ""

@app.route('/', methods=['GET', 'POST'])
def index():
    resp = {'Msg': 'Welcome to ADD-ON OTX'}
    return jsonify(resp)

@app.route('/file/<path:path>', methods=['GET', 'POST'])
def otx_maliciousFile(path):
    try:
        file_ = folderDir+path
        hash = hashlib.md5(open(file_, 'rb').read()).hexdigest()
        response = isMalicious_file(hash)
        return jsonify(response)
    except:
        return False

@app.route('/hash/<path:path>', methods=['GET', 'POST'])
def otx_malicious_hash(path):
    try:
        file_ = folderDir+path
        hash = hashlib.md5(open(file_, 'rb').read()).hexdigest()
        response = isMalicious_hash(hash)
        return jsonify(response)
    except:
        return False

@app.route('/url/<path:path>', methods=['GET', 'POST'])
def otx_maliciousURL(path):
    response = isMalicious_url(path)
    return jsonify(response)

@app.route('/host/<path:path>', methods=['GET', 'POST'])
def otx_malicious_host(path):
    response = isMalicious_host(path)
    return jsonify(response)

@app.route('/ip/<path:path>', methods=['GET', 'POST'])
def otx_malicious_ip(path):
    response = isMalicious_ip(path)
    return jsonify(response)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True, threaded=True)


## <<<< Test-Input >>>>
## http://0.0.0.0:5000/file/<<path>>
## http://0.0.0.0:5000/hash/<<path>>
## http://0.0.0.0:5000/url/<<path>>
## http://0.0.0.0:5000/host/<<path>>
## http://0.0.0.0:5000/ip/<<path>>