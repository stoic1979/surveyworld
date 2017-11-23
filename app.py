from flask import Flask, request, make_response, render_template, jsonify,\
    session, url_for, redirect, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from flask_admin import Admin, BaseView, expose
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
import time
from datetime import datetime, timedelta
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb
from werkzeug.utils import secure_filename
from wtforms.fields import SelectField
from utils import log
from eve import Eve

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'templates')
# app = Eve('survey_app', template_folder=tmpl_dir)

app = Flask(__name__, static_path='/static')
bcrypt = Bcrypt(app)
mdb = Mdb()


##############################################################################
#                                                                            #
#                                                                            #
#                                    SESSION                                 #
#                                                                            #
#                                                                            #
##############################################################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    flask.session.modified = True
    flask.g.user = flask_login.current_user
    # print'session in working'


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


##############################################################################
#                                                                            #
#         _id of mongodb record was not getting JSON encoded, so             #
#                          using this custom one                             #
#                                                                            #
#                                                                            #
##############################################################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#               LOGIN MANAGER                #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


##############################################
#                                            #
#               GET MAC ADDRESS              #
#                                            #
##############################################
def get_mac():
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac


##############################################
#                                            #
#               WHO AM I ROUTE               #
#                                            #
##############################################
@app.route('/user/whoami')
def whoami():
    ret = {}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
        email = session['email']
        ret['Session'] = email
        ret['User_Id'] = mdb.get_user_id_by_session(email)
    except Exception as exp:
        ret['error'] = 1
        ret['user'] = 'user is not login'
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
#                                           #
#        NOT USING THIS AT THE MOMENT       #
#                                           #
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
@app.route('/login_old')
def login_old():
    auth = request.authorization

    if auth and auth.password == 'password':
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'user': auth.username, 'exp': expiry},
                           app.config['secretkey'], algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify!', 401,
                         {'WWW-Authenticate': 'Basic realm="Login Required"'})


##############################################################################
#                                                                            #
#                                                                            #
#                                USER PANNEL                                 #
#                                                                            #
#                                                                            #
##############################################################################
@app.route('/user')
@app.route('/')
def user():
    templateData = {'title': 'Login Page'}
    return render_template('user/index.html', session=session)


#############################################
#                                           #
#               SIGNUP ROUTE                #
#                                           #
#############################################
@app.route('/user/signup')
def signin():
    # templateData = {'title': 'Signup Page', 'questions': question}
    templateData = {'title': 'Signup Page'}
    return render_template('user/signup.html', session=session, **templateData)


#############################################
#                                           #
#                  ADD USER                 #
#                                           #
#############################################
@app.route("/user/add_user", methods=['POST'])
def add_user():
    try:
        user = request.form['user']
        contact = request.form['contact']
        email = request.form['email']
        password = request.form['password']
        question = request.form['question']
        answer = request.form['answer']


        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            print"This Email Already Used"
            templateData = {'title': 'Signup Page'}
            return render_template('user/signup.html', **templateData)

        else:
            mdb.add_user(user, contact, email, pw_hash, question, answer)
            print('User Is Added Successfully')

            return render_template('user/index.html', session=session)

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/user/login', methods=['POST'])
def login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']


        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)

            
            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return render_template('user/index.html', session=session)

        else:
            # Login Failed!
            return render_template('user/index.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return render_template('user/index.html', session=session)


#############################################
#                                           #
#                CREATE SURVEY              #
#                                           #
#############################################
@app.route('/user/create_survey')
def survey():
    temp_data = {'title': 'create_survey'}
    return render_template('user/create_survey.html', session=session)


#############################################
#                                           #
#                SAVE SURVEY                #
#                                           #
#############################################
@app.route("/user/save_survey", methods=['POST'])
def save_survey():

    # survery dictionary to be saved in db
    survey = {}

    try:

        title = request.form['title']
        rowCount = int(request.form['rowCount'])
        ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
        email = session['email']

        survey['title'] = title
        survey['rowCount'] = rowCount
        survey['session_id'] = email
        survey['TimeStamp'] = ts

        # adding all keys/values in form dict
        for i in range(1, rowCount+1):
            print "Reading Key%d" % i
            try:
                survey['ques_id%d' % i] = rowCount = request.form['key%d' % i]
                survey['ques_description%d' % i] = rowCount = \
                    request.form['value%d' % i]
                # survey['type%d' % i] = rowCount = request.form['type%d' % i]
            except:
                print "Key%d not  found" % i

        check = mdb.check_title(title)
        if check:
            return render_template('user/create_survey.html', session=session)

        else:
            mdb.add_survey(survey)
            return render_template('user/save_survey.html', session=session)

    except Exception as exp:
        print('save_survey() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#                GET SURVEY                 #
#                                           #
#############################################
@app.route("/user/get_surveys", methods=['GET'])
def get_surveys():
    surveys = mdb.get_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('user/get_survey.html', **templateData)


#############################################
#                                           #
#              SEARCHING SURVEY             #
#                                           #
#############################################
@app.route('/user/search_survey', methods=['POST'])
def search_survey():
    try:
        text = request.form['survey']
        surveys = mdb.search_survey_for_response(text)

        templateData = {'title': 'Searching..', 'surveys': surveys}
        return render_template('user/get_survey.html', **templateData)

    except Exception as exp:
        print('search_survey() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#               CREATE RESPONSE             #
#                                           #
#############################################
@app.route("/user/create_response", methods=['GET'])
def create_response():
    id = request.args.get("id")
    responses = mdb.get_responses_by_id(id)
    survey = mdb.get_survey(id)

    temp_data = {'title': 'Survey Response', 'survey': survey,
                 'responses': responses}
    return render_template('user/create_response.html', **temp_data)


#############################################
#                                           #
#               Upload                      #
#                                           #
#############################################
dir_path = os.path.dirname(os.path.realpath(__file__))
file_path = '%s/%s' % (dir_path, 'upload')

UPLOAD_FOLDER = file_path
ALLOWED_EXTENSION = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


#############################################
#                                           #
#              PATH OF IMAGE                #
#                                           #
#############################################
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSION


#############################################
#                                           #
#               SAVE RESPONSE               #
#                                           #
#############################################
@app.route('/user/save_response', methods=['POST'])
def save_response():

    # response dictionary to be saved in db
    response = {}
    prefix = request.base_url[:-len('/user/save_response')]
    try:
        survey_id = request.form['survey_id']
        title = request.form['survey_title']
        ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
        rowCount = int(request.form['rowCount'])
        # reading files from request
        pdf_file = request.files['pdf']
        img_file = request.files['pic']

        # pdf upload
        if img_file.filename == '':
            flash('No Selected file')
            return redirect(request.url)
        if pdf_file and allowed_file(pdf_file.filename):
            filename = secure_filename(pdf_file.filename)
            pdf_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            pdf = '%s/%s' % (file_path, filename)
        save_pdf_file_url = "%s/uploads/%s" % (prefix, filename)

        # image upload
        if img_file and allowed_file(img_file.filename):
            filename = secure_filename(img_file.filename)

            img_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            img = '%s/%s' % (file_path, filename)
        save_pic_file_url = "%s/uploads/%s" % (prefix, filename)

        email = session['email']
        response['survey_id'] = survey_id
        response['title'] = title
        response['rowCount'] = rowCount
        response['timeStamp'] = ts
        response['Session_email'] = email
        response['img'] = save_pic_file_url
        response['pdf'] = save_pdf_file_url
        response['img'] = save_pic_file_url
        # response['pdf'] = pdf

        for i in range(1, (rowCount+1)):

            print "Reading Key%d" % i
            try:
                response['ques_description%d' % i] = \
                    request.form['value%d' % i]
            except:
                print "Key%d not  found" % i

        check = mdb.check_survey(title, email)
        if check:
            # update the previous data

            log(response)

            with open('log.json') as json_data:
                data = json.load(json_data)
                print"json file read", data

            mdb.update_survey(data)
        else:
            # save new data

            log(response)

            with open('log.json') as json_data:
                data = json.load(json_data)
                print"json file read", data

            mdb.save_response(data)

    except Exception as exp:
        print('save_response() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('user/save_response.html', session=session)


#############################################
#                                           #
#               SURVEY RESPONSE             #
#                                           #
#############################################
@app.route("/user/get_responses", methods=['GET'])
def get_responses():
    data = mdb.get_responses()
    templateData = {'title': 'Responces', 'data': data}
    return render_template('user/get_responses.html', **templateData)


#############################################
#                                           #
#              SEARCHING SURVEY             #
#                                           #
#############################################
@app.route('/user/search', methods=['POST'])
def search():
    try:
        text = request.form['survey']
        data = mdb.search_survey(text)
        templateData = {'title': 'Searching..', 'data': data}
        return render_template('user/get_responses.html', **templateData)

    except Exception as exp:
        print('search() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#          SHOW SURVEY RESPONSE BY ID       #
#                                           #
#############################################
@app.route("/user/show_survey", methods=['GET'])
def show_survey():
    id = request.args.get("id")
    # survey = mdb.get_survey(id)
    responses = mdb.get_responses_by_id(id)
    templateData = {'title': 'Survey Response',  'responses': responses}
    return render_template('user/show_survey.html', **templateData)


#############################################
#                                           #
#        SEARCHING SURVEY BY ID             #
#                                           #
#############################################
@app.route('/user/search_email', methods=['POST'])
def search_email():
    try:
        text = request.form['email']
        id = request.form['id']
        responses = mdb.search_email(text, id)
        survey = mdb.get_survey(id)
        templateData = {'title': 'Searching..', 'responses': responses, 'survey': survey}
        return render_template('user/show_survey_by_id.html', **templateData)

    except Exception as exp:
        print('search_email() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#              FORGOT PASSWORD              #
#                                           #
#############################################
@app.route('/user/forgot')
def forgot():
    templateData = {'title': 'forgot password'}
    return render_template('user/forgot.html', session=session)


#############################################
#                                           #
#                GET PASSWORD               #
#                                           #
#############################################
@app.route("/user/forgot_password", methods=['POST'])
def forgot_password():
    try:
        email = request.form['email']
        question = mdb.get_security_question(email)
        password = mdb.get_password(email)
        templateData = {'title': 'Security Question Answer',
                        'question': question}
        return render_template('user/security.html',
                               session=session, **templateData)
    except Exception as exp:
        print 'forgot_password():: Got exception: %s' % exp
        print(traceback.format_exc())


#############################################
#            GET SECURITY ANSWER            #
#############################################
@app.route('/user/security_answer', methods=['POST'])
def security_answer():
    try:
        answer = request.form['answer']
        match_answer = mdb.get_security_answer(answer)
        if not match_answer:
            templateData = {'title': 'Security Answer',
                            'question': question}
            redirect('user/scurity.html')
        templateData = {'title': 'Security Question Answer',
                        'email': match_answer}
        return render_template('user/reset_password.html',
                               session=session, **templateData)
    except Exception as exp:
        print 'security_answer():: Got Exception: %s' % exp
        print(traceback.format_exc())


#############################################
#               RESET PASSWORD              #
#############################################
@app.route('/user/reset_password', methods=['POST'])
def reset_password():
    try:
        email = request.form['email']
        password = request.form['password']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)


        mdb.set_password(email, pw_hash)
        templateData = {'title': 'Security Question Answer'}
        return render_template('user/index.html',
                               session=session, **templateData)
    except Exception as exp:
        print 'reset_password():: Got Exception: %s' % exp
        print(traceback.format_exc())


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/clear')
def clearsession():
    try:
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        return render_template('user/index.html', session=session)
    except Exception as exp:
        return 'clearsession() :: Got Exception: %s' % exp


#############################################
#                                           #
#          GET LOGIN INFORMATION            #
#                                           #
#############################################
@app.route('/get_info')
def get_info():
    try:
        LOGIN_TYPE = 'User Login'
        sumSessionCounter()
        email = session['email']
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')

        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)
        return 'User_email: %s, IP: %s, ' \
               'User-Agent: %s' % (user_email, ip, agent, LOGIN_TYPE)
    except Exception as exp:
        print('get_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return ('get_info() :: Got exception: %s is '
                'not found Please Login first' % exp)


##############################################################################
#                                                                            #
#                                                                            #
#                                    ADMIN PANNEL                            #
#                                                                            #
#                                                                            #
##############################################################################
@app.route('/admin')
def admin():
    templateData = {'title': 'index page'}
    return render_template('admin/index.html', **templateData)


#############################################
#                                           #
#                  GET USER                 #
#                                           #
#############################################
@app.route("/admin/get_users", methods=['GET'])
def get_users():
    users = mdb.get_users()
    templateData = {'title': 'Users', 'users': users}
    return render_template('admin/get_users.html', **templateData)


#############################################
#                                           #
#                GET SURVEYS                #
#                                           #
#############################################
@app.route("/admin/get_surveys", methods=['GET'])
def get_surveys_admin():
    surveys = mdb.get_all_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('admin/get_survey.html', **templateData)


#############################################
#                                           #
#                 GET RESPONSES             #
#                                           #
#############################################
@app.route("/admin/get_responses", methods=['GET'])
def get_responses_admin():
    responses = mdb.get_responses_admin()
    templateData = {'title': 'Responces', 'responses': responses}
    return render_template('admin/get_responses.html', **templateData)


#############################################
#                                           #
#                 LOGIN ADMIN               #
#                                           #
#############################################
@app.route('/admin/admin_login', methods=['POST'])
def admin_login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.admin_exists(email, password):
            email = mdb.get_admin_name(email)
            session['email'] = email

            expiry = datetime.datetime.utcnow() + datetime.\
                timedelta(minutes=30)
            token = jwt.encode({'user': email, 'exp': expiry},
                               app.config['secretkey'], algorithm='HS256')
            ret['msg'] = 'Login successful'
            ret['err'] = 0
            ret['token'] = token.decode('UTF-8')
            return render_template('admin/index.html', session=session)
        else:
            templateData = {'title': 'singin page'}
            # Login Failed!
            return render_template('/admin/index.html', session=session)
            # return "Login faild"
            ret['msg'] = 'Login Failed'
            ret['err'] = 1

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
        # return jsonify(ret)
        return render_template('admin/index.html', session=session)


#############################################
#                                           #
#           ADMIN SESSION LOGOUT            #
#                                           #
#############################################
@app.route('/clear1')
def clearsession1():
    session.clear()
    return render_template('/admin/index.html', session=session)


##############################################################################
#                                                                            #
#                                                                            #
#                                APIs                                        #
#                                                                            #
#                                                                            #
##############################################################################
#############################################
#                                           #
#                 GET RESPONSE              #
#                                           #
#############################################
@app.route('/app/get_responses', methods=['GET'])
def get_responses_api():
    responses = mdb.get_responses()
    return JSONEncoder().encode({'responses': responses})


#############################################
#                                           #
#           GET SURVEY RESPONSE             #
#                                           #
#############################################
@app.route('/app/get_survey_responses', methods=['GET'])
def get_survey_responses_api():
    get_survey_responses = mdb.get_responses_admin()
    get_survey_responses_json = JSONEncoder().encode(get_survey_responses)

    # survey response write in log file(In json format)
    file = open("log-file/survey-responses.txt", "w")
    file.write('%s' % get_survey_responses_json)
    file.close()
    return JSONEncoder().encode({'Survey_responses': get_survey_responses})


#############################################
#                                           #
#                 GET SESSION               #
#                                           #
#############################################
@app.route('/app/get_session', methods=['GET'])
def get_session_api():
    session = mdb.get_sessions()
    return JSONEncoder().encode({'session': session})


##############################################################################
#                                                                            #
#                                                                            #
#                              WORKING                                       #
#                                                                            #
#                                                                            #
##############################################################################
#############################################
#                                           #
#                 USER CHART                #
#                                           #
#############################################
@app.route('/user/chart')
def chart():
    chart = mdb.get_chart_survey()
    line_chart = JSONEncoder().encode(chart)

    temp_data = {'title': 'Line Chart', 'chart': chart}
    return render_template('user/chart.html', **temp_data)


#############################################
#                                           #
#                   Error 404               #
#                                           #
#############################################
@app.errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', (request.path))
    return render_template('admin/404.html'), 404


##############################################################################
#                                                                            #
#                                                                            #
#                                      MAIN SERVER                           #
#                                                                            #
#                                                                            #
##############################################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
