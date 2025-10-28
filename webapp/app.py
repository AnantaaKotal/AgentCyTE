from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xml'}

app = Flask(__name__)
app.secret_key = 'coretopogenweb'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'scenario' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['scenario']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flash('Scenario uploaded successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Only XML allowed.')
            return redirect(request.url)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
