import string
import random
from db import Mdb
from random import randint
import json
# import CSV
import time


mdb = Mdb()


def random_str(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def create_test_schedule():

    a = {'name': random_str(6)}
    mdb.db.test_schedule.insert(a)
    print "test_schedule created Successfully..!"


def log(response):
    # file = 'log.json'
    file = './' + path + '/' + filename + '.json'
    with open(file, 'w') as fp:
        json.dump(response, fp)
        print"json file created"

path = './'
filename = 'log'


# scraper utils

SCRAPPER_SLEEP_MIN = 30  # in seconds
SCRAPPER_SLEEP_MAX = 60  # in seconds


def get_request_headers():
    agents = ['Mozilla/5.0', 'Safari/533.1', 'Chrome/33.0.1750.117']
    return {'User-Agents': agents[randint(0, len(agents)-1)]}


def get_rand_in_range(min, max):
    return randint(min, max)


def get_scrapper_sleep():
    return get_rand_in_range(SCRAPPER_SLEEP_MIN, SCRAPPER_SLEEP_MAX)


def sleep_scrapper(scrapper_name):
    val = get_scrapper_sleep()
    print "\n\n[%s] :: SLEEPING FOR %d seconds.....\n\n" % (scrapper_name, val)
    time.sleep(val)
    print "\n\n[%s] :: RESUMED \n\n" % scrapper_name


def scraper_csv_file(msg):
    msg = msg.encode("utf-8")
    file = open("MissingKidsScraper.csv", "a")
    file.write("%s\n" % msg)
    file.close()


if __name__ == "__main__":

    create_test_schedule()
