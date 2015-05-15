#!/usr/bin/env python3

"""
A simple wrapper around pymongo for storing ACDC CCH data

Specific for experiments samples 
requies sleekxmpp:
sudo pip3 install pymongo 
sudo apt-get install python3-dateutil

NOTE: This is an unsupported version using MongoDB as a database.
      The current version uses postgres

   (c) Copyright 2015 Tigran Avanesov, SnT, University of Luxembourg

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

"""

import os
import sys
import json

import logging
log = logging.getLogger(os.path.basename(__file__))
log.setLevel(logging.DEBUG)
loggerfilehandler = logging.FileHandler('./mongolib.log')
loggerfilehandler.setLevel(logging.DEBUG)
# create console handler with a higher log level
loggerconsolehandler = logging.StreamHandler()
loggerconsolehandler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
loggerfilehandler.setFormatter(formatter)
loggerconsolehandler.setFormatter(formatter)
# add the handlers to the logger
log.addHandler(loggerfilehandler)
log.addHandler(loggerconsolehandler)


import pymongo
from pymongo import MongoClient
from bson.dbref import DBRef
from bson.objectid import ObjectId

import re
import dateutil.parser
import datetime
from bson.code import Code

reducer_counter = Code("""
               function(obj, prev){
                 prev.count++;
               }
               """)

class ACDCExpDB:

        # a regexp to extract experiment, tool, partner
        # 
        headerexp = re.compile("\s*\[(.*?)\]\s*\[(.*?)\]\s*\[(.*?)\](.*)")

	# if these keys appear in report, they will be stripped, if the corresponding option is set
        keys_to_strip = ['sample_b64']
        new_value_for_stripped = 'stripped'

        def __init__(me, dbname, host='localhost', port=27017, rewrite = False):
            """
            host: host running mongo server
            port: port for mongo server 
            dbname: database name
            rewrite: remove the database if existed
            """
            me.dbn = dbname
            me.dbclient = MongoClient(host, port,  tz_aware=True)
            if rewrite: 
                    if dbname in me.dbclient.database_names():
                            me.dbclient.drop_database(dbname)
            me.db = me.dbclient[dbname]

            """
            me.users = me.db.create_collection('users')
            """
            me.reports  = me.db['reports']

            #indexes
            #me.reports.ensure_index("report_category")
            #me.reports.ensure_index("timestamp")
            #me.reports.ensure_index("source_key")

            me.reports.ensure_index([("report.report_category", pymongo.ASCENDING), ("report.timestamp", pymongo.ASCENDING)])

            me.reports.ensure_index("meta_data.reported_at")
            me.reports.ensure_index("report.report_category")
            me.reports.ensure_index("report.timestamp")
            me.reports.ensure_index("report.source_key")
            # optional field:
            me.reports.ensure_index("report.reported_at")

            # experiment-specific keys; parsed from report_type
            me.reports.ensure_index("_exp") # experiment name 
            me.reports.ensure_index("_tool") # tool name
            me.reports.ensure_index("_partn") # partner name
        
        @staticmethod
        def __parse_exp(report):
                if report is None: 
                    log.warning("No report_type found! ")
                # e.g. "report_type": "[DDOS][HONEYNET][TID] Login attack by TI+D Kippo honeypot report"
                m = ACDCExpDB.headerexp.match(report)
                res = {}
                if m is None: 
                    log.warning("Could not determine experiment, tool and partner from report_type")
                else: 
                    res['_exp'], res['_tool'], res['_partn'], *desc = m.groups()

                return  res

        def addReport(me, report, remove_sample=True):
                """ adds a new report to the DB """
                experiments = ACDCExpDB.__parse_exp(report.get('report_type', None) or report.get('report', {}).get('report_type', None))

                # parsing date/time
                ts = report.get('meta_data', {}).get('reported_at', None) 
                if ts is not None: 
                    report['meta_data']['reported_at'] = dateutil.parser.parse(ts)
                ts = report.get('report', {}).get('reported_at', None) 
                if ts is not None: 
                    report['report']['reported_at'] = dateutil.parser.parse(ts)
                ts = report.get('report', {}).get('timestamp', None) 
                if ts is not None: 
                    report['report']['timestamp'] = dateutil.parser.parse(ts)
                
                if remove_sample: 
                    for k in ACDCExpDB.keys_to_strip: 
                        if k in report['report']:	
                            report['report'][k] = ACDCExpDB.new_value_for_stripped	

                me.reports.insert(dict(report, **experiments))
        
        def get_different_experiments(me):
                return me.reports.distinct('_exp')
        def get_exp_count(me):
                ppl = [{'$group' : {'_id' : "$_exp", 'total' : { '$sum' : 1 }}}]
                return me.reports.aggregate(ppl)['result']
                # slow version: return me.reports.group(key={'_exp':1}, condition={}, initial={"count":0}, reduce=reducer_counter)

        def get_partn_count(me):
                ppl = [{'$group' : {'_id' : "$_partn", 'total' : { '$sum' : 1 }}}]
                return me.reports.aggregate(ppl)['result']

        def get_tool_count(me):
                ppl = [{'$group' : {'_id' : "$_tool", 'total' : { '$sum' : 1 }}}]
                return me.reports.aggregate(ppl)['result']
                
        def get_dynamics_by_day(me, start=None, end = None):
                """ get statistics per day for a given period of time (datetime) 
                        if the end is None, takes today """
                pipeline = [         
                    { 
                        '$match' : {
                               'report.timestamp': {
                                        '$gt' : start, 
                                        '$lt' : end
                                }
                        },
                    },
                    {
                        '$group' : {
                                  '_id': {
                                      'year' : { '$year' : "$report.timestamp" },        
                                      'month' : { '$month' : "$report.timestamp" },        
                                      'day' : { '$dayOfMonth' : "$report.timestamp" },
                                  },
                                  'count': { '$sum': 1 }
                        }
                    },
                    {
                        '$sort' : {'_id': pymongo.ASCENDING}
                    }
                ]
                return me.reports.aggregate(pipeline)['result']


class Garbage:

        def findUser(me, username, passwd= None):
                """ looks for the first record with given username and password and returns the document; None if not found """
                query = {'user':username}
                if passwd: query['pwd'] =  passwd
                doc = me.users.find_one(query)
                return doc

        def findUserID(me, username, passwd= None):
                """ looks for the first record with given username and password and returns its ID; None otherwise """
                doc = me.findUser(username, passwd)
                if doc:
                        return doc['_id']
                return None

        def findUserDBRef(me, username, passwd= None):
                uid = me.findUserID(username, passwd)
                if uid is None: return None
                return DBRef('users', uid)


        def updateUser(me, uid, userdata):
                user = me.users.find_one({'_id': uid})
                if user:
                        user.update(userdata)
                        me.users.update({'_id': uid}, {'$set': userdata})

        def addUser(me, userdata):
                """ Adds a new user, if not exists, and returns a pair of its ID and timezone """
                # Could probably be done with upsert  (upsert = True flag in update) or .save()
                user = me.findUser(userdata['user'], userdata['pwd'])
                if user is  None: 
                        uid = me.users.insert(userdata)
                        tzone = userdata.get('TZ')
                else:
                        uid = user['_id'] 
                        # update record, e.g. if some fields are missing
                        user.update(userdata)
                        me.users.update({'_id': uid}, {'$set': userdata})
                        tzone = user.get('TZ') or userdata.get('TZ')
                        
                return uid, tzone
        
        def addData(me, uid, datatype, data):
                uref = DBRef('users', uid)
                for record in data:
                        record['user'] = uref
                        if datatype == 'geo':
                                me.geos.insert(record)
                        if datatype == 'act':
                                me.acts.insert(record)


        def getCursorFor(me, login, datatype):
                """Get db cursor for data of datatype (geo or act) fro the given login 
                        (assumes identifiable by login only)"""
                dbref = me.finduserDBRef(login)
                if dbref is None: return None

                if datatype == 'geo':
                        return me.geos.find({'user': dbref}, sort = [('TS', pymongo.ASCENDING)])
                if datatype == 'act':
                        return me.acts.find({'user': dbref}, sort = [('TS', pymongo.ASCENDING)])


        def getKMLbyUID(me, uid):
                if uid:
                        return ddkmlbuilder.getKML(uid, me.users, me.geos, me.acts, me.getSetupDatabyUID(uid))
        
        def getKMLbyLogin(me, login):
                uid = me.findUserID(login)
                return me.getKMLbyUID(uid)
        
        def writeKMLFiles(me, path, prefix="user-"):
                """ writes kml per each user into folder path (creates one if not exists) 
                        filenames start wiwth @prefix
                """
                if not os.path.exists(path):
                        os.makedirs(path)

                for rec in me.users.find():
                        with open(os.path.join(path, prefix+str(rec['_id'])+".kml"), "w") as f:
                                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                                f.write(ddkmlbuilder.getKMLString(ddkmlbuilder.getKML(rec['_id'], me.users, me.geos, me.acts, me.getSetupDatabyUID(rec['_id']))))
        
        def getSetupDatabyUID(me, uid):
                """ returns setup info, like addresses of home/work 
                        note that is is possible that we have multiple entries of setup.
                        Have to choose full one
                """
                dbref = DBRef(me.users.name, uid) 
                setups = me.acts.find({'user':dbref, 'act' : 'setup'}).sort('TS', pymongo.ASCENDING)

                # calulate the measure of the setup entry ( fuller etc) 
                def addrmeasure(addr):
                        """ number of fields with >3 symbols (amongst city and street) """
                        return (1 if len(addr['street'])> 3  else 0) + ( 1 if len( addr['city'] ) > 3 else 0 ) # for python 2.x
                measure = {'work' : -1, 'home': -1, 'transport' : -1}
                setup = {'work' : {}, 'home': {}, 'lunch': {}, 'transport' : []}
                # choosing the 'best filled' and 'most recent' values for setup
                for s in setups: 
                        updlunch = False
                        for addr in ['work', 'home']:
                                curm = addrmeasure(s[addr]) 
                                if curm >= measure[addr]:
                                        setup[addr]=s[addr]
                                        measure[addr] = curm
                                        updlunch = True # if we update home or work addr, we also update lunch time (note also the ascending order by TS)
                        curm = len(s['transport'])
                        if (curm >= measure['transport']) and (curm > 0):
                                measure['transport'] = curm
                                setup['transport'] = s['transport']

                        if updlunch:
                                setup['lunch'] = s['lunch']
                        #log.info(pprint.pformat(s))
                return setup

        def __testAddress(me): 
                """ changed work?  mirimarlo@hotmail.com """
                for rec in me.users.find().skip(0).limit(225):
                        dbref = DBRef(me.users.name, rec['_id']) 
                        print( "0000000000000000000 ", rec['user'] , ' 000000000000000000')
                        tmp = ddkmlbuilder.getSetup(dbref, me.acts)
                        pprint(tmp)

                 

if __name__ == "__main__":
        import doctest
        doctest.testmod()

        db=ACDCExpDB("acdcexp")
        data =  {
                  "report": {
                          "reported_at": "2014-12-01T21:03:37Z",
                              "report_category": "eu.acdc.malicious_uri",
                                  "source_value": "http://drivers.downloadatoz.com/download/198917/sis-7012-audio-driver-c-media.exe",
                                      "report_id": "547cd7a9776562030f73d300",
                                          "report_subcategory": "malware",
                                              "timestamp": "2014-12-01T22:03:36+01:00",
                                                  "confidence_level": 1.0,
                                                      "report_type": "[Websites][cyscon][CSIRT] A URI detected doing malicious activities",
                                                          "version": 1,
                                                              "source_key": "uri"
                                                                },
                    "meta_data": {
                            "domain": "drivers.downloadatoz.com",
                                "report_id": "547cd7a9776562030f73d300",
                                    "country_code": "US",
                                        "api_key_id": 366,
                                            "ip": "67.225.138.160",
                                                "reported_at": "2014-12-01T21:03:37.150Z",
                                                    "status": "NEW",
                                                        "asn": "AS32244",
                                                            "id": 1262617,
                                                                "tld": "com"
                                                                  }
                    }

        db.addReport(data)
