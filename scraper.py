#
# script for scraping missing chlidren from missingkids
#
import requests
import traceback
from bs4 import BeautifulSoup
from utils import get_request_headers, scraper_csv_file
from db import Mdb

mdb = Mdb()


class MissingKidsScraper:

    def __init__(self, state):
        self.state = state

    def run(self):

        try:

            url = 'https://api.missingkids.org/missingkids' \
                  '/servlet/PubCaseSearchServlet?' \
                  'act=usMapSearch&missState=%s&searchLang=en_US&casedata=' \
                  'latest' % self.state

            print '[MissingKidsScraper] :: fetching data from url: %s' % url

            r = requests.get(url, headers=get_request_headers())
            if not r.status_code == 200:
                print '[MissingKidsScraper] :: failed to ' \
                      'get content of url: %s' % url

                return

            html_doc = r.content
            soup = BeautifulSoup(html_doc, 'html.parser')
            for td in soup.find_all('td', width="40%"):
                self.scrap_result_row(td)

            # sleep_scrapper('MissingKidsScraper')

        except Exception as exp:
            print '[MissingKidsScraper] :: run() :: Got exception: %s' % exp
            print(traceback.format_exc())

    def scrap_result_row(self, td):
        try:
            bs = td.text.strip()

            data = bs.split('\n')

            name = data[0]
            print '[MissingKidsScraper] :: Total_details :: Name: ', name
            nyc = data[2]
            print '[MissingKidsScraper] :: Total_details :: Nyc: ', nyc
            dob = data[9]
            if dob == '       ':
                dob = 'Not found'
            print '[MissingKidsScraper] :: Total_details :: DOB: ', dob
            age = data[13]
            if age == 'Missing:':
                age = 0
            print '[MissingKidsScraper] :: Total_details :: Age: ', age
            missing = data[16]
            if missing == '      Race:':
                missing = ' Not Found'
            print '[MissingKidsScraper] :: Total_details :: Missing: ', missing
            location = data[22]
            if location == '      ':
                location = 'Not found'
            print '[MissingKidsScraper] :: Total_details ' \
                  ':: Location: ', location

            # alerts
            alert = td.find('span', class_='alerts').text.strip()
            print '[MissingKidsScraper] :: Total_details :: Alert: ', alert

            # save in db
            # mdb.scraper_data(name, nyc, dob, age, missing, location, alert)

            # save in csv file
            msg = '%s, %s, %s, %s, %s, %s, %s' % (name, nyc, dob, age,
                                                  missing, location, alert)
            scraper_csv_file(msg)

        except Exception as exp:
            print '[MissingKidsScraper] :: scrap_result_row()' \
                  ' :: Got exception: %s' % exp
            print(traceback.format_exc())


if __name__ == '__main__':
    scrapper = MissingKidsScraper('VA')
    scrapper.run()
