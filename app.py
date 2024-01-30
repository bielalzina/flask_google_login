import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("Google Login App")
app.secret_key = "MyVerySecretKey"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID ="551627343701-p4rmqpb0c6c6o7dh1fiopn5cqdblmqnp.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
        ],
    redirect_uri="http://127.0.0.1:5000/callback"
    )

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            # Authorization REQUIRED
            return abort(401)
        else:
            return function()
    return wrapper



@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        # STATE DOES NOT MATCH
        abort(500)
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # return id_info

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")





@app.route("/logout")
def logout():
    session.clear()
    return "ADEU <a href='/'><button>INICI</button></a>"


@app.route("/")
def index():
    return "HOLA <a href='/login'><button>LOGIN</button></a>"


@app.route("/protected_area")
@login_is_required
def protected_area():
    return "PROTECTED <a href='/logout'><button>LOGOUT</button></a>"

if __name__ == "__main__":
    app.run(debug=True)