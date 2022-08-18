import logging
import os

import dash
import jwt
from dash import Dash, Input, Output, State, dcc, html
from flask import Flask, session, url_for
from flask_caching import Cache
from flask_dance.consumer import oauth_authorized
from flask_dance.consumer.storage.sqla import (OAuthConsumerMixin,
                                               SQLAlchemyStorage)
from flask_login import (LoginManager, UserMixin, current_user, login_user,
                         logout_user)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

from cryptr_oauth_blueprint import CryptrOAuth2ConsumerBlueprint

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# CREDIT: This code is copied from Dash official documentation:
# https://dash.plotly.com/urls

# Since we're adding callbacks to elements that don't exist in the app.layout,
# Dash will raise an exception to warn us that we might be
# doing something wrong.
# In this case, we're adding the elements through a callback, so we can ignore
# the exception.
# Exposing the Flask Server to enable configuring it for logging in
server = Flask(__name__)
app = Dash(__name__, 
        server=server,
        title='Example Dash login',
        update_title='Loading...',
        suppress_callback_exceptions=True,
)

cache = Cache(config={'CACHE_TYPE': 'SimpleCache', 'DEBUG': True, "CACHE_DEFAULT_TIMEOUT": 300})

cache.init_app(server)

# Updating the Flask Server configuration with Secret Key to encrypt the user session cookie
server.config.update(SECRET_KEY=os.getenv('SECRET_KEY'), SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI'), SQLALCHEMY_TRACK_MODIFICATIONS=True)


idp_ids = os.getenv('CRYPTR_IDP_IDS').split(',') if os.getenv('CRYPTR_IDP_IDS') else []

cryptr_blueprint = CryptrOAuth2ConsumerBlueprint(
    "cryptr", 
    __name__,
    os.getenv('CRYPTR_TENANT_DOMAIN'),
    client_id=os.getenv('CRYPTR_FRONT_CLIENT_ID'),
    client_secret=os.getenv('CRYPTR_CLIENT_SECRET'),
    base_url=os.getenv('CRYPTR_BASE_URL'),
    jwks_base_url=os.getenv('CRYPTR_JWKS_BASE_URL'),
    scope=os.getenv('CRYPTR_SCOPE'),
    audience=os.getenv('CRYPTR_AUDIENCE'),
    dedicated_server=os.getenv('CRYPTR_DEDICATED_SERVER', 'false') == true,
    production_mode=(os.getenv('CRYPTR_PRODUCTION_MODE') == 'true' if os.getenv('CRYPTR_PRODUCTION_MODE') else True)
)

server.register_blueprint(cryptr_blueprint, url_prefix="/login")

db = SQLAlchemy(server)

# Login manager object will be used to login / logout users
login_manager = LoginManager(server)

# User data model. It has to have at least self.id as a minimum


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True)

class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)

@login_manager.user_loader
def load_user(user_id):
    logger.debug(f'try to fetch user {user_id}')
    return User.query.get(int(user_id))

cryptr_blueprint.storage = SQLAlchemyStorage(OAuth, db.session, user=current_user)


@oauth_authorized.connect
def cryptr_logged_in(blueprint, token):
    logger.debug('cryptr: %s', 'logged_in')
    if blueprint.name == 'cryptr' and 'access_token' in token and 'id_token' in token:
        id_token = token['id_token']
        decoded = jwt.decode(id_token, options={'verify_signature': False, 'verify_aud': False})
        username = decoded['email']
        query = User.query.filter_by(username=username)
        try:
            user = query.one()
        except NoResultFound:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        
        login_user(user)


# User status management views


# Login screen
login = html.Div([dcc.Location(id='url_login', refresh=True),
                  html.H2('''Please log in to continue:''', id='h1'),
                  dcc.Input(placeholder='Enter your username',
                            type='text', id='uname-box'),
                  dcc.Input(placeholder='Enter your password',
                            type='password', id='pwd-box'),
                  html.Button(children='Login', n_clicks=0,
                              type='submit', id='login-button'),
                  html.Div(children='', id='output-state'),
                  html.Br(),
                  dcc.Link('Home', href='/')])

# Successful login
success = html.Div([html.Div([html.H2('Login successful.'),
                              html.Br(),
                              dcc.Link('Home', href='/')])  # end div
                    ])  # end div

# Failed Login
failed = html.Div([html.Div([html.H2('Log in Failed. Please try again.'),
                             html.Br(),
                             html.Div([login]),
                             dcc.Link('Home', href='/')
                             ])  # end div
                   ])  # end div

# logout
logout = html.Div([html.Div(html.H2('You have been logged out - Please login')),
                   html.Br(),
                   dcc.Link('Home', href='/')
                   ])  # end div

# Callback function to login the user, or update the screen if the username or password are incorrect


@app.callback(
    Output('url_login', 'pathname'), Output('output-state', 'children'), [Input('login-button', 'n_clicks')], [State('uname-box', 'value'), State('pwd-box', 'value')])
def login_button_click(n_clicks, username, password):
    if n_clicks > 0:
        if username == 'test' and password == 'test':
            user = User(username)
            login_user(user)
            return '/success', ''
        else:
            return '/login', 'Incorrect username or password'


# Main Layout
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    dcc.Location(id='redirect', refresh=True),
    dcc.Store(id='login-status', storage_type='session'),
    html.Div(id='user-status-div'),
    html.Br(),
    html.Hr(),
    html.Br(),
    html.Div(id='page-content'),
])


index_page = html.Div([
    dcc.Link('Go to Page 1 (magic link)', href='/page-1'),
    html.Br(),
    dcc.Link('Go to Page 2 (SSO)', href='/page-2'),
])

page_1_layout = html.Div([
    html.H1('Page 1'),
    dcc.Dropdown(
        id='page-1-dropdown',
        options=[{'label': i, 'value': i} for i in ['LA', 'NYC', 'MTL']],
        value='LA'
    ),
    html.Div(id='page-1-content'),
    html.Br(),
    dcc.Link('Go to Page 2', href='/page-2'),
    html.Br(),
    dcc.Link('Go back to home', href='/'),
])


@app.callback(Output('page-1-content', 'children'),
              [Input('page-1-dropdown', 'value')])
def page_1_dropdown(value):
    return 'You have selected "{}"'.format(value)


page_2_layout = html.Div([
    html.H1('Page 2'),
    dcc.RadioItems(
        id='page-2-radios',
        options=[{'label': i, 'value': i} for i in ['Orange', 'Blue', 'Red']],
        value='Orange'
    ),
    html.Div(id='page-2-content'),
    html.Br(),
    dcc.Link('Go to Page 1', href='/page-1'),
    html.Br(),
    dcc.Link('Go back to home', href='/')
])


@app.callback(Output('page-2-content', 'children'),
              [Input('page-2-radios', 'value')])
def page_2_radios(value):
    return 'You have selected "{}"'.format(value)


@app.callback(Output('user-status-div', 'children'), Output('login-status', 'data'), [Input('url', 'pathname')])
def login_status(url):
    ''' callback to display login/logout link in the header '''
    # if "cryptr_oauth_token" in session \
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated \
            and url != '/logout':  # If the URL is /logout, then the user is about to be logged out anyways
        if current_user:
            logger.debug('current_user present')
            logger.debug(current_user.is_authenticated)
            logger.debug('current_user %s', current_user.id)
        logger.debug('session %s\n', session)
        return html.Div([
            html.H1(f'Bonjour {current_user.username}'),
            dcc.Link('logout', href='/logout'),
            ]), current_user.is_authenticated
    else:
        return dcc.Link('login', href='/login'), 'loggedout'

# Main router

def cryptr_url(**kwargs):
    for key, value in kwargs.items():
        session[key] = value
    return url_for('cryptr.login')


@app.callback(Output('page-content', 'children'), Output('redirect', 'pathname'),
              [Input('url', 'pathname')])
def display_page(pathname):
    ''' callback to determine layout to return '''
    # We need to determine two things for everytime the user navigates:
    # Can they access this page? If so, we just return the view
    # Otherwise, if they need to be authenticated first, we need to redirect them to the login page
    # So we have two outputs, the first is which view we'll return
    # The second one is a redirection to another page is needed
    # In most cases, we won't need to redirect. Instead of having to return two variables everytime in the if statement
    # We setup the defaults at the beginning, with redirect to dash.no_update; which simply means, just keep the requested url
    view = None
    url = dash.no_update
    if isinstance(current_user, User):
        logger.debug('cryptr: should be authorized: %s', current_user)
    else:
        logger.debug('cryptr: should not be authorized')
    
    current_user_present = isinstance(current_user, User)

    if pathname == '/login':
        view = login
    elif pathname == '/success':
        # if current_user.is_authenticated:
        if current_user_present:
            view = success
        else:
            view = failed
    elif pathname == '/logout':
        if current_user_present:
            # logout_user()
            view = logout
            query = OAuth.query.filter_by(user_id=current_user.id)
            try:
                oauth = query.one()
                session['refresh_token'] = oauth.token['refresh_token']
            except NoResultFound as not_found_error:
                logger.warning("Cryptr Oauth error: %s", str(not_found_error))
            url = url_for('cryptr.logout')
        else:
            view = login
            url = '/login'

    elif pathname == '/page-1':
        if current_user_present:
            view = page_1_layout
        else:
            view = 'Redirecting to magic link login...'
            url = cryptr_url(sso_gateway=False, locale='fr')
    elif pathname == '/page-2':
        if current_user_present:
            view = page_2_layout
        else:
            view = 'Redirecting to sso login...'
            url = cryptr_url(sso_gateway=True, idp_ids=idp_ids, locale='fr')
    else:
        view = index_page
    # You could also return a 404 "URL not found" page here
    return view, url


if __name__ == '__main__':
    app.run_server(debug=True)
