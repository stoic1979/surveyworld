from apscheduler.schedulers.blocking import BlockingScheduler
from auto_survey import post_survey
from scraper import MissingKidsScraper

sched = BlockingScheduler()
missingKids = MissingKidsScraper('VA')


@sched.scheduled_job('interval', minutes=59)
def timed_job():
    missingKids.run()
    post_survey()
    print('This job is run every 59 minutes.')


@sched.scheduled_job('cron', day_of_week='mon-fri', hour=17)
def scheduled_job():
    print('This job is run every weekday at 5pm.')

sched.start()
