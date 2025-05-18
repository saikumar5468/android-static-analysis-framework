from flask import Flask, request, render_template, jsonify, flash, redirect, url_for
import os
import uuid
import logging
from werkzeug.utils import secure_filename
from static_analysis import analyze_apk

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'apk'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB limit

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = os.urandom(24)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file part")
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected")
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        logger.info(f"File saved: {file_path}")

        try:
            result = analyze_apk(file_path)
            return render_template('results.html', result=result, filename=filename)
        except Exception as e:
            logger.error(f"Error analyzing APK: {e}")
            flash("Failed to analyze APK.")
            return redirect(url_for('home'))
    else:
        flash("Invalid file type. Only .apk files are allowed.")
        return redirect(url_for('home'))


# Optional: clean uploaded files after request lifecycle or schedule cleanup jobs

if __name__ == '__main__':
    app.run(debug=True)
