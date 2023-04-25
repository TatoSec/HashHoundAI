from flask import Flask
from flask import request
import os
import hashlib

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <html>
    <head>
    <title>Upload new File</title>
    </head>
    <body>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    </body>
    </html>
    '''

@app.route('/hashes', methods=['POST'])
def handle_hashes():
    hash_value = request.form['hash']
    md5_hash = hashlib.md5(hash_value.encode()).hexdigest()
    sha1_hash = hashlib.sha1(hash_value.encode()).hexdigest()
    sha256_hash = hashlib.sha256(hash_value.encode()).hexdigest()
    return f'''
    <html>
    <head>
    <title>HashHoundAI</title>
    </head>
    <body>
    <h1>HashHoundAI</h1>
    <h2>Results for your hash</h2>
    <p>MD5: {md5_hash}</p>
    <p>SHA-1: {sha1_hash}</p>
    <p>SHA-256: {sha256_hash}</p>
    </body>
    </html>
    '''


@app.route('/')
def home():
    return '''
    <html>
    <head>
    <title>HashHoundAI</title>
    </head>
    <body>
    <h1>HashHoundAI</h1>
    <h2>Understand your files, know your environment</h2>
    <form action="/hashes" method="post">
        <label for="hash">Enter Hash:</label>
        <input type="text" id="hash" name="hash">
        <input type="submit" value="Submit">
    </form>
    <br>
    <form action="/upload">
        <input type="submit" value="Upload File">
    </form>
    </body>
    </html>
    '''