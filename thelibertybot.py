#!/usr/bin/python3 -u

# =============================================================================
# IMPORTS
# =============================================================================
import configparser
import logging
import logging.handlers
import time
import os
import sys
import praw
import prawcore
import yaml
import re
import sqlite3
from datetime import datetime, timedelta
import pprint
pp = pprint.PrettyPrinter(indent=4)


# =============================================================================
# GLOBALS
# =============================================================================
# Reads the config file
config = configparser.ConfigParser()
config.read("bot.cfg")
config.read("auth.cfg")

Settings = {}
Settings = {s: dict(config.items(s)) for s in config.sections()}
Settings['SubConfig'] = {}

ENVIRONMENT = config.get("BOT", "environment")
DEV_USER_NAME = config.get("BOT", "dev_user")
RUNNING_FILE = "bot.pid"
os.environ['TZ'] = 'US/Eastern'

#LOG_LEVEL = logging.INFO
LOG_LEVEL = logging.DEBUG
LOG_FILENAME = Settings['Config']['logfile']
LOG_FILE_INTERVAL = 2
LOG_FILE_BACKUPCOUNT = 5
LOG_FILE_MAXSIZE = 5000 * 256

# Define custom log level 5=trace
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, 'TRACE')
def trace(self, message, *args, **kws):
        self.log(TRACE_LEVEL, message, *args, **kws) 
logging.Logger.trace = trace

logger = logging.getLogger('bot')
logger.setLevel(LOG_LEVEL)
log_formatter = logging.Formatter('%(levelname)-8s:%(asctime)s:%(lineno)4d - %(message)s')
log_stderrHandler = logging.StreamHandler()
log_stderrHandler.setFormatter(log_formatter)
logger.addHandler(log_stderrHandler)
if LOG_FILENAME:
    log_fileHandler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='d', interval=LOG_FILE_INTERVAL, backupCount=LOG_FILE_BACKUPCOUNT) 
    log_fileHandler.setFormatter(log_formatter)
    logger.addHandler(log_fileHandler)
logger.propagate = False



# =============================================================================
# FUNCTIONS
# =============================================================================
def create_running_file():
    # creates a file that exists while the process is running
    running_file = open(RUNNING_FILE, "w")
    running_file.write(str(os.getpid()))
    running_file.close()


def create_db():
    # create database tables if don't already exist
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        ccur = con.cursor()
        ccur.execute("CREATE TABLE IF NOT EXISTS processed (id TEXT, epoch INTEGER)")
        con.commit
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()

def check_message_processed_sql(messageid):
    logging.debug("Check processed for id=%s" % messageid)
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT id FROM processed WHERE id=?''', (messageid,))
        row = qcur.fetchone()
        if row:
            return True
        else:
            return False
    except sqlite3.Error as e:
        logger.error("SQL Error:" % e)
    finally:
        if con:
            con.close()

def mark_message_processed_sql(messageid):
    logging.debug("Mark message processed for id=%s" % messageid)
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT id FROM processed WHERE id=?''', (messageid,))
        row = qcur.fetchone()
        if row:
            return True
        else:
            icur = con.cursor()
            insert_time = int(round(time.time()))
            icur.execute("INSERT INTO processed VALUES(?, ?)",
                         [messageid, insert_time])
            con.commit()
            return True
    except sqlite3.Error as e:
        logger.error("SQL Error:" % e)
    finally:
        if con:
            con.close()

def build_multireddit_groups(subreddits):
    """Splits a subreddit list into groups if necessary (due to url length)."""
    multireddits = []
    current_multi = []
    current_len = 0
    for sub in subreddits:
        if current_len > 3300:
            multireddits.append(current_multi)
            current_multi = []
            current_len = 0
        current_multi.append(sub)
        current_len += len(sub) + 1
    multireddits.append(current_multi)
    return multireddits

def create_default_wiki_page(SubName):
    # read default wiki page text from file
    default_wiki_page_content = ""
    with open('defaultwiki.txt') as f:
        default_wiki_page_content = f.read()
    reddit.subreddit(SubName).wiki.create('thelibertybot', default_wiki_page_content, reason='Inital Settings Page Creation')
    reddit.subreddit(SubName).wiki['thelibertybot'].mod.update(listed=False,permlevel=2)

def get_subreddit_settings(SubName):
    # either use settings from wikipage or defaults from Config
    wikipage = ""
    wikidata = ""

    if SubName not in Settings['SubConfig']:
        Settings['SubConfig'][SubName] = {}
        Settings['SubConfig'][SubName]['userexceptions'] = []

    try:
      wikipage = reddit.subreddit(SubName).wiki['thelibertybot']
      wikidata = yaml.safe_load(wikipage.content_md)
      if not wikidata:
          logger.error("%s - EMPTY WikiPage - Creating Default" % SubName)
          create_default_wiki_page(SubName)
          wikipage = reddit.subreddit(SubName).wiki['thelibertybot']
          wikidata = yaml.safe_load(wikipage.content_md)
    except Exception:
        # send_error_message(requester, subreddit.display_name,
        #    'The wiki page could not be accessed. Please ensure the page '
        #    'http://www.reddit.com/r/{0}/wiki/{1} exists and that {2} '
        #    'has the "wiki" mod permission to be able to access it.'
        #    .format(subreddit.display_name,
        #            cfg_file.get('reddit', 'wiki_page_name'),
        #            username))
        # create a default wiki page and set to be unlisted and mod edit only
        logger.error("%s - No WikiPage - Creating Default" % SubName)
        create_default_wiki_page(SubName)
        wikipage = reddit.subreddit(SubName).wiki['thelibertybot']
        wikidata = yaml.safe_load(wikipage.content_md)

    # use settings from subreddit wiki else use defaults
    settingkeys = [
                   'reportapprove_feature', 'reportapprove_list', 
                   'submissionstatement_feature', 'submissionstatement_min_length', 'submissionstatement_grace_minutes',
                   'userexceptions'
                  ]

    for key in settingkeys:
        if key in wikidata:
            Settings['SubConfig'][SubName][key] = wikidata[key]
        elif key not in Settings['SubConfig'][SubName] and key in Settings['Config']:
            Settings['SubConfig'][SubName][key] = Settings['Config'][key]

    # append the subs moderators to user exction list for the sub
    for moderator in reddit.subreddit(SubName).moderator():
        if moderator.name not in  Settings['SubConfig'][SubName]['userexceptions']:  # This is me!
            Settings['SubConfig'][SubName]['userexceptions'] += [moderator.name]

    logger.trace("%s SETTINGS %s" % (SubName, Settings['SubConfig'][SubName]))

def get_mod_permissions(SubName):
    am_moderator = False
    my_permissions = None
    # Get the list of moderators.
    list_of_moderators = reddit.subreddit(SubName).moderator()

    # Iterate over the list of moderators to see if we are in the list
    for moderator in list_of_moderators:
        if moderator == Settings['Reddit']['username']:  # This is me!
            am_moderator = True  # Turns out, I am a moderator, whoohoo
            # Get the permissions I have as a list. e.g. `['wiki']`
            my_permissions = moderator.mod_permissions
    logger.trace("%s PERMS - Mod=%s Perms=%s" % (SubName, am_moderator, my_permissions))


def check_comment(comment):
    authorname = ""
    subname = ""
    searchsubs = []
    subname = str(comment.subreddit).lower()
    authorname = str(comment.author.name)
    User_Score=0

    logger.info("%-20s: process comment: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M', time.localtime(comment.created_utc)), authorname, comment.permalink))
    mark_message_processed_sql(comment.id)

    # skip any user exceptions
    if re.search('bot',str(authorname),re.IGNORECASE):
            logger.info("%-20s:   bot user skip" % subname)
            return
    if authorname.lower() == "automoderator":
            logger.info("%-20s:   automoderator user skip" % subname)
            return
    if 'userexceptions' in Settings['SubConfig'][subname]:
        if authorname.lower() in (name.lower() for name in Settings['SubConfig'][subname]['userexceptions']):
            logger.info("%-20s:   userexceptions, skipping: %s" % (subname,authorname))
            return

def check_submission(submission):
    authorname = ""
    subname = ""
    searchsubs = []
    subname = str(submission.subreddit.display_name).lower()
    authorname = str(submission.author)
    User_Score=0

    # skip any user exceptions
    if re.search('bot',str(authorname),re.IGNORECASE):
            logger.trace("    bot user skip")
            mark_message_processed_sql(submission.id)
            return
    if authorname.lower() == "automoderator":
            logger.trace("    bot user skip")
            mark_message_processed_sql(submission.id)
            return
    if 'userexceptions' in Settings['SubConfig'][subname]:
        if authorname.lower() in (name.lower() for name in Settings['SubConfig'][subname]['userexceptions']):
            logger.debug("    userexceptions, skipping: %s" % authorname)
            mark_message_processed_sql(submission.id)
            return

    logger.debug("%-20s: process submission: %s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(submission.created_utc)), submission.author, submission.permalink))

    # Skip any item already approved by a moderator
    #
    approved_by = str(submission.approved_by)
    if approved_by and approved_by != "None":
        logger.info(" --- Approved by(skipping): (%s)" % approved_by)
        mark_message_processed_sql(submission.id)
        return
   
    # Processing for submission statement
    # 
    if 'submissionstatement_feature' in Settings['SubConfig'][subname] and Settings['SubConfig'][subname]['submissionstatement_feature']:
        logger.debug("-- SUBMISSION STATEMENT PROCESSING: %s" % submission.permalink)
        # Check if the submission has a valid submission statement.
        
        # skip self_text posts
        #if submission.is_self:
        #   logger.debug("-- Self-Text Post, Skipping %s", submission.permalink)
        #   mark_message_processed_sql(submission.id)
        #   return True

        post_time = datetime.utcfromtimestamp(submission.created_utc)
        current_time = datetime.utcnow()

        # Number of whole minutes (seconds / 60) between post time and current time
        mins_since_post = int((current_time - post_time).seconds / 60)
        if mins_since_post < int(Settings['SubConfig'][subname]['submissionstatement_grace_minutes']):
            # If it hasn't been up long enough, don't remove, but check later.
            logger.debug("-- SS grace time used: %s / %s" % (mins_since_post, Settings['SubConfig'][subname]['submissionstatement_grace_minutes']))
            return
        for top_level_comment in submission.comments:
            if top_level_comment.is_submitter:
                REGEX_SS_LOCATE = r'(ss|submission statement):.{%s}' % Settings['SubConfig'][subname]['submissionstatement_min_length']
                if re.search(REGEX_SS_LOCATE, top_level_comment.body):
                    logger.info("-- SS valid, mark complete %s", submission.permalink)
                    mark_message_processed_sql(submission.id)
                    return

        # No valid top level comment from OP and time has expired, remove post, and Let them know
        logger.info("-- SS Grace EXPIRED, removing post")
        submission.mod.remove()
        submission.mod.lock()


        SS_REMOVAL_NOTICE  = "**NOTICE: Your post has been automatically removed for not including a valid submission statement.**\n\n"
        SS_REMOVAL_NOTICE += "All posts must be accompanied by a submission statement from the OP indicating the posts relevance to libertarian discussions. "
        SS_REMOVAL_NOTICE += "A submission statement is a 2+ sentence comment in reply to your post, in your own words, that describes why the post is relevant to the sub.  "
        SS_REMOVAL_NOTICE += "Posts with inadequate, or incomplete submission statements will be removed.  "
        SS_REMOVAL_NOTICE += "To include a submission statement, create a top-level comment on your own post of the following format:\n\n"
        SS_REMOVAL_NOTICE += "---\n\n" 
        SS_REMOVAL_NOTICE += "SS: This is a long comment about why this submission is relevent and on-topic. It should also be in your own words.\n\n"
        SS_REMOVAL_NOTICE += "---\n\n" 
        SS_REMOVAL_NOTICE += "If you still wish to share your post, you must resubmit your post accompanied by a submission statement of at least %s characters.\n\n" % Settings['SubConfig'][subname]['submissionstatement_min_length']
        SS_REMOVAL_NOTICE += "*This is a bot.  Replies will not receive a response.*\n"

        removal_comment = submission.reply(SS_REMOVAL_NOTICE)
        removal_comment.mod.lock()
        removal_comment.mod.distinguish(sticky=True)


def check_modqueuereport(reportitem):
    subname = ""
    subname = str(reportitem.subreddit.display_name).lower()

    if not Settings['SubConfig'][subname]['reportapprove_feature'] or not Settings['SubConfig'][subname]['reportapprove_list']:
       return

    if reportitem.name.startswith("t1"):
        reportType = "Comment"
    elif reportitem.name.startswith("t3"):
        reportType = "Submission"
    else:
        return

    for user_report in reportitem.user_reports:
        for reportsearch in Settings['SubConfig'][subname]['reportapprove_list']:
            if len(reportitem.user_reports) == 1 and reportsearch in user_report[0]:
                logger.info("%-20s: AUTO APPROVE modqueue %s item: %s user=%s http://reddit.com%s %s" % (subname, reportType, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(reportitem.created_utc)), str(reportitem.author), str(reportitem.permalink), user_report[0]))
                reportitem.mod.ignore_reports()
                reportitem.mod.approve()

# =============================================================================
# MAIN
# =============================================================================


def main():
    start_process = False
    logger.info("start program")

    # create db tables if needed
    logger.trace("Create DB tables if needed")
    create_db()

    if ENVIRONMENT == "DEV" and os.path.isfile(RUNNING_FILE):
        os.remove(RUNNING_FILE)
        logger.debug("DEV=running file removed")

    if not os.path.isfile(RUNNING_FILE):
        create_running_file()
        start_process = True
    else:
        logger.error("bot already running! Will not start.")

    # Initalize
    next_refresh_time = 0
    subList = []
    subList_prev = []

    while start_process and os.path.isfile(RUNNING_FILE):
        logger.debug("Start Main Loop")
        subList = [ 'subwatchbottest' ]

        # Only refresh settings once an hour
        if int(round(time.time())) > next_refresh_time:
            logger.debug("REFRESH Start")
            for SubName in subList:
                get_subreddit_settings(SubName)
            logger.info("subList: %s" % subList)
            next_refresh_time = int(
                round(time.time())) + (60 * int(Settings['Config']['config_refresh_mins']))
            logger.info("--- Settings REFRESH Completed")
            logger.debug("%s" % Settings['SubConfig'])

        if not subList == subList_prev:
           logger.debug("Build(re) multireddit")
           multireddits = build_multireddit_groups(subList)
           for multi in multireddits:
            #subreddit = reddit.subreddit(settings.REDDIT_SUBREDDIT)
             subreddit = reddit.subreddit('+'.join(multi))
           subList_prev = subList

        subreddit = reddit.subreddit('+'.join(multi))
        modqueue_stream = subreddit.mod.stream.reports(pause_after=-1)
        submission_stream = subreddit.stream.submissions(pause_after=-1)
#        comment_stream = subreddit.stream.comments(pause_after=-1)

        try:
          # process modqueue stream
          logger.debug("MAIN-Check modqueue")
          for reportitem in modqueue_stream:
            if reportitem is None:
              break
            else:
              check_modqueuereport(reportitem)

          # process submission stream
          logger.debug("MAIN-Check submissions")
          for submission in submission_stream:
            if submission is None:
               break
            elif check_message_processed_sql(submission.id):
               continue
            else:
               check_submission(submission)

#          # process comment stream
#          logger.debug("MAIN-Check comments")
#          for comment in comment_stream:
#            if comment is None:
#               break
#            elif check_message_processed_sql(comment.id):
#               continue
#            else:
#               check_comment(comment)


        # Allows the bot to exit on ^C, all other exceptions are ignored
        except KeyboardInterrupt:
            break
        except Exception as err:
            logger.exception("Unknown Exception in Main Loop: %s", err)

        logger.debug("End Main Loop - Pause %s secs" % Settings['Config']['main_loop_pause_secs'])
        time.sleep(int(Settings['Config']['main_loop_pause_secs']))

    logger.info("end program")
    sys.exit()


# =============================================================================
# RUNNER
# =============================================================================

if __name__ == '__main__':
    # Reddit info
    reddit = praw.Reddit(client_id=Settings['Reddit']['client_id'],
                         client_secret=Settings['Reddit']['client_secret'],
                         password=Settings['Reddit']['password'],
                         user_agent=Settings['Reddit']['user_agent'],
                         username=Settings['Reddit']['username'])
    main()
