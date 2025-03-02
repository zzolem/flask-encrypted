import random, os, json
from flask import Flask, render_template, session, request
from flask_encrypted import Encrypted
""" Size test of encrypted_session_aesgcm.py
Data consists of random json, a little text and some base64
    >>>> original data size = 2274
    >>>> compressed data size = 1151
    >>>> encrypted size = 1167
    >>>> encrypted b64 size = 1556
    >>>> entire cookie size = 1584 """

""" base85 has 7% less space overhead compared to base64
    python implementation is 7 times slower with 16 byte strings
    and 22 times slower with 128 byte strings """
""" base91, if properly implemented, is as fast as base64
    base91 does produce printable ASCII """

app = Flask(__name__)

app.config['SESSION_MAX_AGE_TTL'] = True
app.config.update(
#    SESSION_ENCRYPTION = "aesgcm",
    SECRET_KEY = b'7\xb4%\xe4=YFoz\x98\x14,\x13\xf6y>', # 128 bits
    SESSION_COOKIE_NAME = "pineapple",
    PERMANENT_SESSION = False,
    PERMANENT_SESSION_LIFETIME = 3 * 60 * 60, # Can also be datetime.datetime obj
    SESSION_TTL = 60 * 60,
    SESSION_TTL_RESET_PER_REQUEST = False,
    SESSION_COOKIE_SAMESITE = None,
)
Encrypted(app)

@app.route ('/', methods=['GET'])
def root():
    r = random.randint (1,10)
    session['randint'] = r
    session['bloat64'] = b'TG9yZW0gSXBzdW0gaXMgc2ltcGx5IGR1bW15IHRleHQgb2YgdGhlIHByaW50aW5nIGFuZCB0eXBlc2V0dGluZyBpbmR1c3RyeS4gTG9yZW0gSXBzdW0gaGFzIGJlZW4gdGhlIGluZHVzdHJ5J3Mgc3RhbmRhcmQgZHVtbXkgdGV4dCBldmVyIHNpbmNlIHRoZSAxNTAwcywgd2hlbiBhbiB1bmtub3duIHByaW50ZXIgdG9vayBhIGdhbGxleSBvZiB0eXBlIGFuZCBzY3JhbWJsZWQgaXQgdG8gbWFrZSBhIHR5cGUgc3BlY2ltZW4gYm9vay4gSXQgaGFzIHN1cnZpdmVkIG5vdCBvbmx5IGZpdmUgY2VudHVyaWVzLCBidXQgYWxzbyB0aGUgbGVhcCBpbnRvIGVsZWN0cm9uaWMgdHlwZXNldHRpbmcsIHJlbWFpbmluZyBlc3NlbnRpYWxseSB1bmNoYW5nZWQuIEl0IHdhcyBwb3B1bGFyaXNlZCBpbiB0aGUgMTk2MHMgd2l0aCB0aGUgcmVsZWFzZSBvZiBMZXRyYXNldCBzaGVldHMgY29udGFpbmluZyBMb3JlbSBJcHN1bSBwYXNzYWdlcywgYW5kIG1vcmUgcmVjZW50bHkgd2l0aCBkZXNrdG9wIHB1Ymxpc2hpbmcgc29mdHdhcmUgbGlrZSBBbGR1cyBQYWdlTWFrZXIgaW5jbHVkaW5nIHZlcnNpb25zIG9mIExvcmVtIElwc3VtLg=='
    
    return render_template ('test_form.html')

@app.route ('/', methods=['POST'])
def form_handler():
    guess = int(request.form['guess'])
    if guess == session['randint']:
        status = "RIGHT"
    else:
        status = "WRONG"
        
    m = {'guess': guess, 'status': status}

    ttl = session['_ttl'] if session.get('_ttl') else None
    return render_template ('test_form.html', m=m, ttl=ttl)

if __name__ == '__main__':
    app.run(threaded=True, debug=True) # Debug
