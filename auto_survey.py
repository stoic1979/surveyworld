from utils import random_str
import requests
from flask import Flask, request, make_response, render_template, jsonify,\
    session, url_for, redirect, flash, send_from_directory
import os
from db import Mdb
from config import devflag
import json
import traceback
from pprint import pprint


app = Flask(__name__, static_path='/static')
mdb = Mdb()


def create_survey_response():

    survey_json = {'title': random_str(12),
                   'rowCount': random_str(12),
                   'session_id': random_str(12),
                   'ques_id1': random_str(12),
                   'ques_id2': random_str(12),
                   'ques_id3': random_str(12),
                   'ques_id4': random_str(12),
                   'ques_description1': random_str(12),
                   'ques_description2': random_str(12),
                   'ques_description3': random_str(12),
                   'ques_description4': random_str(12),

                   }
    """
                   'type1': random_str(12),
                   'type2': random_str(12),
                   'type3': random_str(12),
                   'type4': random_str(12)
                   """

    return survey_json


def post_survey():

    survey_json = create_survey_response()

    if not devflag:
        print 'flag running on local'
        url = 'http://0.0.0.0:5000/api/survey'
    else:
        print 'flag running on remote'
        url = 'https://fathomless-crag-' \
              '93337.herokuapp.com/api/survey'

    print '[INFO] post_survey() :: post url %s' % url

    r = requests.post(url, data=survey_json)
    print(r.json())

if __name__ == '__main__':
    post_survey()
