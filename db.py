from pymongo import MongoClient
from config import *
from flask import jsonify
import traceback
import json
import datetime
# from utils import scraper_csv_file
from bson import ObjectId


##############################################################################
#                                                                            #
#                                                                            #
#                                 DATABASE CLASS                             #
#                                                                            #
#                                                                            #
##############################################################################
class Mdb:

    def __init__(self):
        # local db
        conn_str = "mongodb://%s:%s@%s:%d/%s" \
             % (DB_USER, DB_PASS, DB_HOST, DB_PORT, AUTH_DB_NAME)

        # mlab db
        # conn_str = "mongodb://appdbuser1:" \
        #             "appdbuser1@ds157712.mlab.com:57712/heroku_188g0kct"
        client = MongoClient(conn_str)
        # self.db = client['heroku_188g0kct']
        self.db = client['survey_world'] # local db

#############################################
#                                           #
#        GET NAME ACCORDING TO EMAIL        #
#                                           #
#############################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name

##############################################
#                                            #
#       GET SECURITY QUESTION BY EMAIL       #
#                                            #
##############################################
    def get_security_question(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        question = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                question = data['question']
                print 'password in db class', question
        return question

#############################################
#                                           #
#      MATCH SECURITY ANSWER BY EMAIL       #
#                                           #
#############################################
    def get_security_answer(self, answer):
        result = self.db.user.find({'answer': answer})
        name = ''
        password = ''
        question = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                question = data['email']
                print 'password in db class', question
        return question

#############################################
#                                           #
#               GET NEW PASSWORD            #
#                                           #
#############################################
    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print 'password in db class', password
        return password

#############################################
#                                           #
#               SET NEW PASSWORD            #
#                                           #
#############################################
    def set_password(self, email, pw_hash):
        self.db.user.update(
            {'email': email},
            {'$set': {'password': pw_hash}},
            upsert=True, multi=True)

#############################################
#                                           #
#         GET USER ID BY SESSION            #
#                                           #
#############################################
    def get_user_id_by_session(self, email):
        result = self.db.user.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id


#############################################
#                                           #
#             testing IN DATABASE           #
#                                           #
#############################################
    def testing(self, user):
        try:
            rec = {
                'name': user
            }
            self.db.testing.insert(rec)

        except Exception as exp:
            print "testing() :: Got exception: %s", exp
            print(traceback.format_exc())


#############################################
#                                           #
#            ADD USER IN DATABASE           #
#                                           #
#############################################
    def add_user(self, user, contact, email, password, question, answer):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': user,
                'contact': contact,
                'email': email,
                'password': password,
                'question': question,
                'answer': answer,
                'creation_date': ts

            }
            self.db.user.insert(rec)

        except Exception as exp:
            print "add_user() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#     ADD ADMIN IN DATABASE [HARD CODE]     #
#                                           #
#############################################
    def add_admin(self, email, password):
        try:
            rec = {
                'email': email,
                'password': password
            }
            self.db.admin.insert(rec)
        except Exception as exp:
            print "add_admin() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#            ADD FORM IN DATABASE           #
#                                           #
#############################################
    def user_form(self, user_id, key, value):
        try:
            rec = {
                'user_id': user_id,
                'key': key,
                'value': value
            }
            self.db.survey_form.insert(rec)

        except Exception as exp:
            print "user_form() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#           CHECK USER IN DATABASE          #
#                                           #
#############################################
    def user_exists(self, email):
        """
        function checks if a user with given email and password
        exists in database
        :param email: email of the user
        :param password: password of the user
        :return: True, if user exists,
                 False, otherwise
        """
        return self.db.user.find({'email': email}).count() > 0

    def admin_exists(self, email, password):

        return self.db.admin.find({'email': email, 'password': password}).\
                   count() > 0

#############################################
#                                           #
#            ADD SURVEY IN DATABASE         #
#                                           #
#############################################
    def add_survey(self, survey):
        self.db.survey.insert(survey)

#############################################
#                                           #
#            USER SESSION IN DATABASE       #
#                                           #
#############################################
    def save_login_info(self, user_email, mac, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            # ts = datetime.datetime.utcnow()
            # ts = datetime.datetime.now().strftime("%d-%m-%G  %H:%M:%S")
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")

            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.user_session.insert(rec)
        except Exception as exp:
            print "save_login_info() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#                 GET SESSION               #
#                                           #
#############################################
    def get_sessions(self):
        collection = self.db["user_session"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

#############################################
#                                           #
#                 GET USERS                 #
#                                           #
#############################################
    def get_users(self):
        collection = self.db["user"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

#############################################
#                                           #
#                 GET SURVEY                #
#                                           #
#############################################
    def get_surveys(self):
        collection = self.db["survey"]
        # result = collection.find().skip(self.db.survey.count()-1)
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

    def get_all_surveys(self):
        collection = self.db["survey"]
        # result = collection.find().skip(self.db.survey.count()-1)
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

    def get_survey(self, _id):
        collection = self.db["survey"]
        result = collection.find({'_id': ObjectId(_id)})
        for data in result:
            return data

    def set_password(self, email, passw):
        self.db.user.update(
            {'email': email},
            {'$set': {'password': passw}},
            upsert=True, multi=True)
        print "done"

    def check_survey(self, title, email):
        return self.db.responses.find({'title': title, 'Session_email': email
                                       }).count() > 0

    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0

    def check_title(self, title):
        return self.db.survey.find({'title': title}).count() > 0

    def update_survey(self, response):

        title = response['title']
        Session_email = response['Session_email']
        rowCount = response['rowCount']
        timeStamp = response['timeStamp']
        img = response['img']
        pdf = response['pdf']
        ques_description1 = response['ques_description1']
        ques_description2 = response['ques_description2']
        ques_description3 = response['ques_description3']
        ques_description4 = response['ques_description4']
        survey_id = response['survey_id']

        # mongodb update query
        self.db.responses.update(
            {'title': title, 'Session_email': Session_email},
            {'$set': {'ques_description1': ques_description1,
                      'ques_description2': ques_description2,
                      'ques_description3': ques_description3,
                      'ques_description4': ques_description4,
                      'img': img, 'pdf': pdf}},
            upsert=True, multi=True
        )

    def save_response(self, response):
        self.db.responses.insert(response)

#############################################
#                                           #
#               GET SURVEY BY ID            #
#                                           #
#############################################
    def get_responses_by_id(self, survey_id):
        collection = self.db["responses"]
        result = collection.find({'survey_id': survey_id})
        ret = []
        for data in result:
            # print '---------data', data
            ret.append(data)
        # return JSONEncoder().encode({'responses': ret})
        return ret

#############################################
#                                           #
#             GET RESPONSES USER            #
#                                           #
#############################################
    def get_responses(self):
        collection = self.db["survey"]
        result = collection.find()
        ret = []
        for data in result:

            ret.append(data)
        return ret

#############################################
#                                           #
#             GET perticular response       #
#                                           #
#############################################
    def get_perticular_responses(self, title):
        collection = self.db["survey"]
        result = collection.find({'title': title})
        ret = []
        for data in result:

            ret.append(data)
        return ret

#############################################
#                                           #
#            GET RESPONSES ADMIN            #
#                                           #
#############################################
    def get_responses_admin(self):
        collection = self.db["responses"]
        result = collection.find()
        ret = []
        for data in result:

            ret.append(data)
        return ret

######################################
#        filter from survey id       #
######################################
    def get_responses_from_survey(self, survey_id):
        collection = self.db["responses"]
        result = collection.find({'survey_id': survey_id})
        ret = []
        for data in result:

            ret.append(data)
        return ret

    def get_chart_responses(self):
        collection = self.db["responses"]
        result = collection.find()
        ret = []
        for data in result:

            ret.append(data)
        return ret

    def get_chart_survey(self):
        collection = self.db["survey"]
        result = collection.find()
        ret = []
        for data in result:

            ret.append(data)
        return ret

#############################################
#                                           #
#       Automated Data                      #
#                                           #
#############################################
    def save_automated_data(self, auto_data):
        self.db.survey.insert(auto_data)

#############################################
#                                           #
#               OR Query                    #
#                                           #
#############################################
    def search_survey(self, text):
        result = self.db.survey.find({
            "$or":
                [
                    # {"title": text}
                    # {"title" : { "$regex" : ".*${text}.*"} }
                    {'title': {'$regex': text, '$options': 'i'}}
                 ]
        })
        ret = []
        for data in result:
            ret.append(data)
        return ret
        # print'===========================', ret
    # db.survey.find( { $or:[ {"title": "Help Survey"} ] } )

#############################################
#                                           #
#         OR Query FOR EMAIL SEARCHING      #
#                                           #
#############################################
    def search_email(self, text, id):
        result = self.db.responses.find({
            "$or":
                [
                    {'Session_email': {'$regex': text, '$options': 'i'},
                     'survey_id': {'$regex': id, '$options': 'i'}}
                 ]
        })
        ret = []
        for data in result:
            ret.append(data)
        return ret

#############################################
#                                           #
#               OR Query                    #
#                                           #
#############################################
    def search_survey_for_response(self, text):
        result = self.db.survey.find({
            "$or":
                [
                    # {"title": text}
                    # {"title" : { "$regex" : ".*${text}.*"} }
                    {'title': {'$regex': text, '$options': 'i'}}
                 ]
        })
        ret = []
        for surveys in result:
            ret.append(surveys)
        return ret

    # db.survey.find( { $or:[ {"title": "Help Survey"} ] } )

#############################################
#                                           #
#               OR Query                    #
#                                           #
#############################################
    def scraper_data(self, name, nyc, dob, age, missing, locatoin, alert):
        try:
            rec = {
                'name': name,
                'nyc': nyc,
                'dob': dob,
                'age': age,
                'missing': missing,
                'location': locatoin,
                'alert': alert
            }
            self.db.scraper_data.insert(rec)
        except Exception as exp:
            print '[Mdb] :: scraper_data() :: Got exception: %s' % exp
            print(traceback.format_exc())


if __name__ == "__main__":
    mdb = Mdb()

    ###################################################
    #                                                 #
    #             Quick internal tests                #
    #                                                 #
    ###################################################
    mdb.add_admin('johny@gmail.com', '123')
    # mdb.add_admin('tom@gmail.com', '123')

    # mdb.get_or()
    mdb.search_survey('help')

    # lets write some users
    # mdb.add_user('johny', 'johny@gmail.com', '123')
    # print "user created"

    # lets show all users
    # for user in mdb.db.user.find():
    #    print "User: ", user

    # if mdb.user_exists('johny@gmail.com', '123'):
    #    print "User exists"
    # else:
    #    print "User does not exists"

    # testing
    # mdb.add_admin('john@gmail.com', '123')
    # mdb.add_admin('tom@gmail.com', '123')

    """
    if mdb.user_exists('tom@gmail.com', '123'):
        print 'user exist'
    else:
        print 'user does not exist'
    """
    # mdb.save_login_info('id_123', '192.168.0.1', 'tom', 'User Logout')
    # mdb.get_responses()
    # mdb.get_security_question('tomy@gmail.com')
