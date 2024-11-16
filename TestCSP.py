from flask import Flask, request, render_template_string, redirect, url_for, make_response

app = Flask(__name__)

# Store the CSP header in a global variable (for demonstration purposes only)
# In production, consider more secure storage methods
app.config['CSP_HEADER'] = "default-src 'self';"

# Home Page
@app.route('/')
def home():
    return render_template_string("""
        <h1>Welcome to the CSP Test Application</h1>
        <p>This application allows you to test how different Content Security Policy (CSP) configurations affect the vulnerability of a web page to Cross-Site Scripting (XSS) attacks.</p>
        <ul>
            <li><a href="{{ url_for('set_csp') }}">Set CSP Header</a></li>
            <li><a href="{{ url_for('test_xss') }}">Test XSS Vulnerability</a></li>
        </ul>
    """)

# Route to Set CSP Header
@app.route('/set_csp', methods=['GET', 'POST'])
def set_csp():
    if request.method == 'POST':
        # Get the user-input CSP header
        user_csp = request.form.get('csp_header')
        if user_csp:
            app.config['CSP_HEADER'] = user_csp
            return redirect(url_for('home'))
        else:
            error = "Please enter a valid CSP header."
            return render_template_string("""
                <h2>Set Content Security Policy</h2>
                <p style="color:red;">{{ error }}</p>
                <form method="POST">
                    <label for="csp_header">Content-Security-Policy:</label><br>
                    <input type="text" id="csp_header" name="csp_header" size="100" placeholder="e.g., default-src 'self'; script-src 'self' https://apis.google.com;"><br><br>
                    <input type="submit" value="Set CSP">
                </form>
                <p><a href="{{ url_for('home') }}">Back to Home</a></p>
            """, error=error)
    return render_template_string("""
        <h2>Set Content Security Policy</h2>
        <form method="POST">
            <label for="csp_header">Content-Security-Policy:</label><br>
            <input type="text" id="csp_header" name="csp_header" size="100" placeholder="e.g., default-src 'self'; script-src 'self' https://apis.google.com;"><br><br>
            <input type="submit" value="Set CSP">
        </form>
        <p><a href="{{ url_for('home') }}">Back to Home</a></p>
    """)

# XSS-Prone Route
@app.route('/test_xss', methods=['GET', 'POST'])
def test_xss():
    if request.method == 'POST':
        # Reflect the user input without sanitization (Vulnerable to XSS)
        user_input = request.form.get('user_input', '')
        # Note: Insecure rendering; do not use in production
        response = make_response(render_template_string(f"""
            <h2>Test XSS Vulnerability</h2>
            <p>You entered: {user_input}</p>
            <form method="POST">
                <label for="user_input">Enter text:</label><br>
                <input type="text" id="user_input" name="user_input" size="100"><br><br>
                <input type="submit" value="Submit">
            </form>
            <p><a href="{{{{ url_for('home') }}}}">Back to Home</a></p>
        """))
        # Apply the CSP header
        response.headers['Content-Security-Policy'] = app.config['CSP_HEADER']
        return response
    return render_template_string("""
        <h2>Test XSS Vulnerability</h2>
        <form method="POST">
            <label for="user_input">Enter text:</label><br>
            <input type="text" id="user_input" name="user_input" size="100"><br><br>
            <input type="submit" value="Submit">
        </form>
        <p><a href="{{ url_for('home') }}">Back to Home</a></p>
    """)

if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True)
