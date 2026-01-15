from datetime import datetime, timedelta
import os
import time
import json
from flask import Flask, redirect, url_for, session, render_template, make_response, request, g, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# IMPORTANT: Ensure your .env has a SECRET_KEY
app.secret_key = os.getenv("SECRET_KEY", "a_very_secret_random_string")

# Configure session cookies to be secure
app.config.update(
    SESSION_COOKIE_SECURE=True if not app.debug else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True
)

# OAuth 2.0 Configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@app.before_request
def before_request():
    """Set timestamp for this request"""
    g.start_time = time.time()

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Don't add cache headers to API endpoints - they need to work with cookies
    if request.path != '/api/check-session':
        # Prevent caching for HTML pages only
        if response.content_type and 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    
    # Add other security headers (these are safe for all responses)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Add unique response ID to prevent caching (except for API)
    if request.path != '/api/check-session':
        response.headers['X-Response-ID'] = str(time.time())
    
    return response

@app.route('/')
def login_page():
    response = make_response(render_template('login.html'))
    # Prevent caching of login page
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/login/google')
def login():
    redirect_uri = url_for('authorize', _external=True)
    
    # Check if we should force account selection from cookie
    force_reauth = request.cookies.get('force_reauth')
    
    if force_reauth == 'true':
        # Force account selection
        resp = google.authorize_redirect(redirect_uri, prompt='select_account')
        response = make_response(resp)
        # Clear the force_reauth cookie
        response.set_cookie('force_reauth', '', expires=0, path='/')
        return response
    else:
        return google.authorize_redirect(redirect_uri)

@app.route('/callback')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
    user_info = resp.json()
    
    session['user'] = user_info
    session['login_time'] = datetime.now().isoformat()
    session.permanent = True
    
    return redirect('/landing')

@app.route('/landing')
def landing():
    # Strict access control [cite: 59, 64]
    if 'user' not in session:
        session.clear()
        return redirect(url_for('login_page'))
    
    # Add cache busting parameter
    response = make_response(render_template('landing.html', 
        user=session['user'],
        cache_buster=int(time.time())
    ))
    
    # Force revalidation every time for HTML pages
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    
    return response

# CRITICAL: Add session validation endpoint
@app.route('/api/check-session')
def check_session():
    """API endpoint to check if session is valid"""
    # IMPORTANT: Don't add cache headers to this endpoint - it needs to work with cookies
    if 'user' in session:
        if 'login_time' in session:
            try:
                login_time = datetime.fromisoformat(session['login_time'])
                if (datetime.now() - login_time).seconds > 3600:
                    session.clear()
                    return jsonify({'valid': False, 'reason': 'session_expired'})
            except (ValueError, TypeError):
                session.clear()
                return jsonify({'valid': False, 'reason': 'invalid_session'})
        return jsonify({'valid': True, 'user': session['user']})
    else:
        return jsonify({'valid': False, 'reason': 'no_session'})

@app.route('/logout')
def logout():
    # 1. Destroy the server-side session [cite: 61, 63]
    session.clear()
    
    # 2. Prepare the redirect [cite: 61]
    response = make_response(redirect(url_for('login_page')))
    
    # 3. Explicitly clear the session cookie 
    response.set_cookie('session', '', expires=0, path='/')
    
    # 4. Set a flag to force Google to ask for account selection next time
    response.set_cookie('force_reauth', 'true', max_age=60, path='/')
    
    # 5. Overwrite headers to prevent back-button snapshots 
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    
    # 6. Clear browser storage (works in modern browsers)
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    
    return response

if __name__ == '__main__':
    app.run(debug=True)