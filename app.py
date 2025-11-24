# EnvelopeX v1.0.0 - Professional Email Forensics Platform

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import logging
from werkzeug.utils import secure_filename
import os
from core.analyzer import EmailForensicsAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'envelopex-forensics-v1.0.0'
)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024

ALLOWED_EXTENSIONS = {'eml', 'msg', 'mbox', 'txt', 'emlx'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def api_health():
    import time
    return jsonify({
        'status': 'operational',
        'service': 'EnvelopeX v1.0.0',
        'timestamp': int(time.time() * 1000)
    }), 200


@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    try:
        # Step 1: Parse JSON request
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON format'
            }), 400

        payload = request.get_json()

        # Validate payload structure
        if 'file' not in payload:
            return jsonify({
                'success': False,
                'error': 'Missing file data in request'
            }), 400

        file_data = payload['file']

        # Validate required fields
        required_fields = ['name', 'size', 'extension', 'content']
        missing_fields = [f for f in required_fields if f not in file_data]
        if missing_fields:
            fields_str = ", ".join(missing_fields)
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {fields_str}'
            }), 400

        filename = secure_filename(file_data['name'])
        file_extension = file_data['extension'].lower()

        # Validate extension
        ext_without_dot = file_extension.lstrip('.')
        if ext_without_dot not in ALLOWED_EXTENSIONS:
            supported = ', '.join(ALLOWED_EXTENSIONS)
            return jsonify({
                'success': False,
                'error': (
                    f'Invalid file type: {file_extension}. '
                    f'Supported: {supported}'
                )
            }), 400

        # Step 2: Decode base64 content
        import base64
        try:
            file_content = base64.b64decode(file_data['content'])
        except Exception:
            return jsonify({
                'success': False,
                'error': 'Invalid file content encoding'
            }), 400

        # Validate file content
        if len(file_content) == 0:
            return jsonify({
                'success': False,
                'error': 'Empty file content'
            }), 400

        max_size = app.config['MAX_CONTENT_LENGTH']
        if len(file_content) > max_size:
            max_mb = max_size // (1024 * 1024)
            return jsonify({
                'success': False,
                'error': f'File too large. Maximum: {max_mb}MB'
            }), 400

        logger.info(
            f"Processing email: {filename} ({len(file_content)} bytes)"
        )

        # Step 3: Initialize analyzer
        analyzer = EmailForensicsAnalyzer()

        # Extract metadata
        metadata = payload.get('metadata', {})
        metadata.update({
            'user_agent': request.headers.get('User-Agent'),
            'source_ip': request.remote_addr
        })

        # Step 4: Perform analysis
        analysis_results = analyzer.analyze_email(
            file_content=file_content,
            filename=filename,
            metadata=metadata
        )

        # Step 5: Check for errors
        if 'error' in analysis_results and \
           not analysis_results.get('success', True):
            return jsonify({
                'success': False,
                'error': analysis_results['error'],
                'details': analysis_results.get('file_metadata', {})
            }), 500

        logger.info(f"Analysis completed: {filename}")

        # Step 6: Return comprehensive results
        return jsonify({
            'success': True,
            'data': analysis_results
        })

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'service': 'EnvelopeX Email Forensics',
        'features': [
            'Multi-format parsing (EML, MSG, MBOX)',
            'RFC 5322 header extraction',
            'SPF/DKIM/DMARC validation',
            'IOC extraction (URLs, IPs, domains)',
            'Phishing detection',
            'Attachment analysis',
            'HTML sanitization'
        ]
    })


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({
        'success': False,
        'error': 'File too large. Maximum size: 25MB'
    }), 413


if __name__ == '__main__':
    logger.info("=" * 70)
    logger.info("EnvelopeX v2.0 - Advanced Email Forensics Platform")
    logger.info("=" * 70)
    logger.info("Server: http://127.0.0.1:5000")
    logger.info("Supported formats: EML, MSG, MBOX, TXT")
    logger.info("Features: Full forensic analysis with IOC extraction")
    logger.info("=" * 70)
    
    # Get port from environment variable (for Render/Heroku) or use 5000
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug, host='0.0.0.0', port=port)

