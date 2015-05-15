#!/usr/bin/env python3

"""
A wrapper around postgresql for storing ACDC CCH data

Specific for experiments samples 
requires: 

pip3 install psycopg2
# pip3 install pyasn1 pyasn1_modules
sudo apt-get install python3-dateutil


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
import psycopg2
from psycopg2 import extras


import logging
log = logging.getLogger(os.path.basename(__file__))
log.setLevel(logging.INFO)
loggerfilehandler = logging.FileHandler('./postgreslib.log')
loggerfilehandler.setLevel(logging.INFO)
# create console handler with a higher log level
loggerconsolehandler = logging.StreamHandler()
# TODO
#loggerconsolehandler.setLevel(logging.ERROR)
loggerconsolehandler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
loggerfilehandler.setFormatter(formatter)
loggerconsolehandler.setFormatter(formatter)
# add the handlers to the logger
log.addHandler(loggerfilehandler)
log.addHandler(loggerconsolehandler)


import re
import dateutil.parser
import datetime


def only_alphanum(s):
    if s is not None: 
        return re.sub(r'\W+', '', s)
    else:
        return None
def get_exp_filter(exp): 
    """additional filter by experiment for queries"""
    # escaping dangerous input:
    exp = only_alphanum(exp)
    if exp is not None:  
        # any experiment startin with exp
        return "and (experiment in (select id from experiments where experiment ilike '%s%%')) "%exp
    else:
        return ''

def get_arch_prefix(arch): 
    """ return archive table prefix """ 
    if arch: 
        return "arch_"
    else:
        return ""

def i_dont_read_personal_data(ip):
        #keep 2 first blocks only
        return ":".join(( ".".join(ip.split(".")[:2]) ).split(':')[:2])
        

class ACDCExpDB:

        # a regexp to extract experiment, tool, partner
        # 
        headerexp = re.compile("\s*\[(.*?)\]\s*\[(.*?)\]\s*\[(.*?)\](.*)")

        # if these keys appear in report, they will be stripped, if the corresponding option is set
        keys_to_strip = ['sample_b64']
        new_value_for_stripped = 'stripped'

        def __init__(me, dbname, user, password, host='localhost', port=5432,rewrite = False, commit_every = 100):
            """
            host: host running mongo server
            port: port for mongo server 
            dbname: database name
            ...
            rewrite: remove the database if existed
            commit_every: do a commit every commit_evey insertions
            """


            me.dbn = dbname
            me.dbclient =  None
            me.commit_every = commit_every
            me.inscounter = 0

            try:
                me.dbclient = psycopg2.connect(database=dbname, user = user, password=password, host = host, port = port)
            except psycopg2.DatabaseError as e:
                log.error(e)
                sys.exit(1)


            cur = me.dbclient.cursor()
            me.cur = cur
            # creating tables

            # Experiments, partners and tool
            cur.execute("Create Table If Not Exists experiments(\
            Id smallserial PRIMARY KEY,\
            experiment VARCHAR(128) \
            );")
            cur.execute("Create Table If Not Exists partners(\
            Id smallserial PRIMARY KEY,\
            partner VARCHAR(128) \
            );")
            cur.execute("Create Table If Not Exists tools(\
            Id smallserial PRIMARY KEY,\
            tool VARCHAR(128) \
            );")

            # Source keys
            cur.execute("Create Table If Not Exists source_keys(\
            Id smallserial PRIMARY KEY,\
            source_key VARCHAR(255) \
            );")

            # Report Categories
            # cur.execute("Create Table If Not Exists report_categories(\
            # Id smallserial PRIMARY KEY,\
            # report_category VARCHAR(255) \
            # );")

            # Report sub-Categories
            cur.execute("Create Table If Not Exists report_subcategories(\
            Id smallserial PRIMARY KEY,\
            report_subcategory VARCHAR(255) \
            );")

            # Modes (anonymity ?)
            cur.execute("Create Table If Not Exists modes(\
            Id smallserial PRIMARY KEY,\
            mode VARCHAR(255) \
            );")

            # Alternate format type
            cur.execute("Create Table If Not Exists alternate_format_types(\
            Id smallserial PRIMARY KEY,\
            alternate_format_type VARCHAR(255) \
            );")

            me.helptables = {
              'experiments': 'experiment',
              'partners' : 'partner', 
              'tools' : 'tool', 
              'source_keys' : 'source_key',
              'report_subcategories' : 'report_subcategory', 
              'modes' : 'mode',
              'alternate_format_types' : 'alternate_format_type'
            }

            """
	    Metadata:
	    "meta_data": {
		    "api_key_id": 380,
		    "report_id": "54ca36ae7765622b89d00300",
		    "country_code": "GB",
		    "id": 24361084,
		    "tld": null,
		    "reported_at": "2015-01-29T13:33:34.129Z",
		    "domain": null,
		    "ip": "94.245.70.1",
		    "status": "NEW",
		    "asn": "AS8075"
	    }
	    goes to all tables

	    meta_api_key_id smallint, \
	    meta_country_code VARCHAR(3), \
	    meta_id integer, \
	    meta_tld VARCHAR(64), \
	    meta_reported_at timestamp, \
	    meta_domain VARCHAR(255), \
	    meta_ip VARCHAR(64), \
	    meta_status VARCHAR(16), \
	    meta_asn integer, \  ## smallint is signed, cannot contain asns like 37777
	    """
	    

            me.tables = {} # keys are tables, values are fields (fields = dict field: type)
            me.tables['attack'] = {
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", # stripped 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            "ip_protocol_number": "smallint", 
            "ip_version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "src_ip": "VARCHAR(10)", # stripped 
            "src_mode": "smallint references modes(Id)", 
            "dst_ip": "VARCHAR(10)", # stripped 
            "dst_mode": "smallint references modes(Id)", 
            "src_port": "integer", 
            "dst_port": "integer", 
            "sample_filename": "VARCHAR(255)", 
            "sample_sha256": "VARCHAR(72)", 
            "malicious_uri": "VARCHAR(255)", 
            "subject_text": "VARCHAR(128)" 
            }
            # maybe botnet should be a reference instead of varchar
            

            me.tables['bot'] = {
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            "report_id": "VARCHAR(63)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "ip_version": "smallint", 
            "ip_protocol_number": "smallint", 
            "src_ip_v4": "VARCHAR(8)", 
            "src_ip_v6": "VARCHAR(10)", 
            "src_mode": "smallint references modes(Id)", 
            "src_port": "integer", 
            "c2_ip_v4": "VARCHAR(8)", 
            "c2_ip_v6": "VARCHAR(10)", 
            "c2_mode": "smallint references modes(Id)", 
            "c2_port": "integer", 
            "sample_sha256": "VARCHAR(72)", 
            "fast_flux_uri": "VARCHAR(255)",
            }

            me.tables['botnet']={
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
             #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "reported_at": "timestamp", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            }

            me.tables['c2_server']={
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            "report_id": "VARCHAR(63)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "ip_version": "smallint", 
            "ip_protocol_number": "smallint", 
            "c2_ip_v4": "VARCHAR(8)", 
            "c2_ip_v6": "VARCHAR(10)", 
            "c2_mode": "smallint references modes(Id)", 
            "c2_port": "integer",
            }

            me.tables['fast_flux'] = {
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)",
            }


            me.tables['malicious_uri'] ={
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "ip_version": "smallint", 
            "src_ip_v4": "VARCHAR(8)", 
            "src_ip_v6": "VARCHAR(10)", 
            "src_mode": "smallint references modes(Id)", 
            "sample_filename": "VARCHAR(255)", 
            "sample_sha256": "VARCHAR(72)", 
            "exploits": "smallint default 0",
            }
            # exploits : number of exploits

            me.tables['malware']={
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "mime_type": "VARCHAR(255)", 
            "sample_hashes": "VARCHAR(255)", 
            "exploits": "smallint default 0",
            }
            # exploits : number of exploits; sample hashes is a stringified array


            me.tables['spam_campaign']= {
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "report_id": "VARCHAR(63)", 
            "report_subcategory": "smallint references report_subcategories(Id)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "botnet": "VARCHAR(63)", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "sample_filename": "VARCHAR(255)", 
            "sample_sha256": "VARCHAR(72)", 
            "malicious_uri": "VARCHAR(255)",
            }
            # exploits : number of exploits

            me.tables['vulnerable_uri'] = {
            "Id": "SERIAL PRIMARY KEY",
            "meta_api_key_id": "smallint", 
            "meta_country_code": "VARCHAR(3)", 
            "meta_id": "integer", 
            "meta_tld": "VARCHAR(64)", 
            "meta_reported_at": "timestamp", 
            "meta_domain": "VARCHAR(255)", 
            "meta_ip": "VARCHAR(10)", 
            "meta_status": "VARCHAR(16)", 
            "meta_asn": "integer", 
            "experiment" : "smallint references experiments(Id)",
            "partner" : "smallint references partners(Id)",
            "tool" : "smallint references tools(Id)",
            #"report_category": "smallint references report_categories(Id)", 
            "report_type": "VARCHAR(255)",
            "ts": "timestamp", 
            "source_key": "smallint references source_keys(Id)", 
            "source_value": "VARCHAR(255)", 
            "confidence_level": "real", 
            "version": "smallint", 
            "src_ip_v4": "VARCHAR(8)", 
            "src_ip_v6": "VARCHAR(10)", 
            "src_mode": "smallint references modes(Id)", 
            "vulnerabilities": "smallint default 0", 
            "report_id": "VARCHAR(63)", 
            "duration": "integer", 
            "reported_at": "timestamp", 
            "alternate_format_type": "smallint references alternate_format_types(Id)", 
            "ip_version": "smallint",
            }
            # vulnerabilities : number of vuln


            for t in me.tables:
                    cur.execute("Create Table If Not Exists %s("%t + ",".join("%s %s"%(key,me.tables[t][key]) for key in me.tables[t].keys()) +");")


            me.dbclient.commit()
            # creating indexes
            generic_indexes  = ['ts', 'reported_at', 'partner', 'tool', 'experiment', 'report_subcategory', 'confidence_level', 'meta_asn', 'meta_country_code']
            double_indexes = ['reported_at']
            tripple_indexes = ['experiment']
            for t in me.tables:
                    for idx in generic_indexes:
                            # botnet does not have timestamp field
                            try:
                                    cur.execute("Create index idx_%s_%s on %s(%s);"%(t,idx,t,idx))
                                    log.info('Index created in table %s for field %s', t, idx)
                            except Exception as e:
                               log.warning('Could not create index : %s', e) 
                            finally: 
                               me.dbclient.commit()
                            if idx not in ['ts', 'reported_at', 'meta_reported_at']:
                                for didx in double_indexes: 
                                    try:
                                        cur.execute("Create index idx_%s_%s_%s on %s(%s, %s);"%(t,didx,idx,t,didx,idx))
                                        log.info('Index created in table %s for fields  %s, %s', t, didx, idx)
                                    except Exception as e:
                                       log.warning('Could not create index : %s', e) 
                                    finally: 
                                       me.dbclient.commit()

                                    # tripple idx
                                    if idx not in tripple_indexes:
                                        for tidx in tripple_indexes:
                                            try:
                                                cur.execute("Create index idx_%s_%s_%s_%s on %s(%s, %s, %s);"%(t,didx,tidx,idx,t,didx,tidx,idx))
                                                log.info('Index created in table %s for fields  %s, %s,  %s', t, didx, tidx, idx)
                                            except Exception as e:
                                               log.warning('Could not create index : %s', e) 
                                            finally: 
                                               me.dbclient.commit()

                               
            try:
                    cur.execute("Create index idx_malware_ts_samples on malware(ts, source_value);") # note! source_key is always "malware" in spec...
                    log.info('Index created in table malware for fields ts and source_value')
            except Exception as e:
               log.warning('Could not create index : %s', e) 
            finally: 
               me.dbclient.commit()

            try:
                    cur.execute("Create index idx_malware_ts_samples on malware(ts, mime_type);") 
                    log.info('Index created in table malware for fields ts and mime_type')
            except Exception as e:
               log.warning('Could not create index : %s', e) 
            finally: 
               me.dbclient.commit()
            
            me.dbclient.commit()
  

            if rewrite: 
                raise NotImplementedError
                    #if dbname in me.dbclient.database_names():
                    #        me.dbclient.drop_database(dbname)



            # TODO: add indexes once 

            #indexes
            #me.reports.ensure_index("report_category")
            #me.reports.ensure_index("timestamp")
            #me.reports.ensure_index("source_key")

            """
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
            """
        
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
                    res['experiment'], res['tool'], res['partner'], *desc = m.groups()

                return  res



        def get_id(self, entity, value):
            """
	     entity is a table from which to look for an id (e.g. 'experiments'); 
	     value is a string with the value to look for; 
	     finds and returns the id of a given value;
	     if not found; add new and returns the id
            """
            if entity not in self.helptables: 
                    log.error("Tried to get a non-existing entity. Should not have happened")
                    sys.exit(1)
            #log.debug("SELECT Id from %s where %s"%(entity, tables[entity])  +"= %s")
            #log.debug("VAL: " + value)
            self.cur.execute("SELECT Id from %s where %s"%(entity, self.helptables[entity])  +"= %s", (value,))
            res = self.cur.fetchone()
            if res is None: 
                self.cur.execute("Insert into %s(%s)"%(entity, self.helptables[entity]) + " values (%s) returning Id;", (value,))
                res = self.cur.fetchone()
                self.dbclient.commit() #it should be rare, so let's commit
            if res is not None: 
                return res[0]
            else: 
                return None

        def get_recs(self, entity):
            """
	     entity is a table from which to look for an id (e.g. 'experiments'); 
             finds and returns the dict str(id) : value
             e.g.
             {'1': 'DDOS', '2': "tests'}
            """
            if entity not in self.helptables: 
                    log.error("Tried to get a non-existing entity. Should not have happened")
                    sys.exit(1)
            self.cur.execute("SELECT * from %s;"%entity) 
            lst = self.cur.fetchall()
            """
             e.g.
             [(1, 'DDOS'),
              (2, 'tests'),
               (3, 'WEBSITES'),
                (4, 'Websites'),
                 (5, 'MOBILE'),
                  (6, 'test'),
                   (7, 'SPAM'),
                    (8, 'Test6'),
                     (9, 'Test9'),
                      (10, 'FAST-FLUX'),
                       (11, ''),
                        (12, 'WEBSITE'),
                         (13, 'FastFlux')]
            """
            return {str(x[0]) : x[1] for x in lst}

        def addReport(me, report, remove_sample=True):
                """ adds a new report to the DB """
                experiments = ACDCExpDB.__parse_exp(report.get('report_type', None) or report.get('report', {}).get('report_type', None))
                
                # WARNING: suppose the report does not contain 'partner', 'tool', 'experiment' fields
                report.update(experiments)

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

                # Look at different report category to know where to put the record
                categ = report.get('report', {}).get('report_category')
                if categ is None:
                        log.warning("Report has no report_category! skipping")
                        return
                table = categ.split('.')[-1] # getting the last part of eu.acdc.attack

                if table not in me.tables:
                        log.error("Unknown report category %s, ignoring! Please, investigate the problem", table)
                        return

                # getting data from report and putting to the corresponding table
                fields=me.tables[table]
                values = {}
                for field in fields.keys():
                        repfield = field
                        if field == 'ts': 
                                repfield = 'timestamp'
                        val = None
                        if field.startswith('meta_'):
                                repfield = field[5:]
                                val = report.get('meta_data', {}).get(repfield)
                        elif field in ['experiment', 'partner', 'tool']:
                                val = report.get(repfield)
                        else: 
                                val = report.get('report', {}).get(repfield)
                        if val is not None:
                                if repfield == 'asn': 
                                        if val.upper().startswith('AS'):
                                                val = val[2:]
                                elif repfield in ['ip','src_ip','dst_ip','src_ip_v4','src_ip_v6','c2_ip_v4','c2_ip_v6'] :
                                        val = i_dont_read_personal_data(val)
                                elif repfield in ['experiment', 'partner', 'tool', 'source_key', 'mode', 'alternate_format_type'] :# if a reference in another table
                                        val = me.get_id(repfield+"s", val)
                                elif repfield.endswith('_mode'):
                                        val = me.get_id('modes', val)
                                elif repfield == 'report_subcategory':
                                        val = me.get_id('report_subcategories', val)
                                elif repfield in ['vulnerabilities', 'exploits']: # for those just take the length
                                        val = len(val)

                                # avoiding problems with inserting dictionaries/lists with psycopg2
                                if isinstance(val, (dict, list)):
                                    val=str(val)

                                values[field] = val
                                # truncating all varchars here...
                                # could also do in execute 'asdasdf'::varchar(4)
                                if  'varchar' in  fields[field].lower(): 
                                        lngth = int(re.sub("\D", "", fields[field]))
                                        values[field] = val[:lngth]




                # not sure if .keys and .values keep the same order...
                # so used items()
                flds, vals =  (x for x in zip(*values.items()))
                num = len(flds) # number of fields to add

                insertstring = "Insert into %s("%table + (",".join(["%s"]*num))%flds  + ") values("+ ",".join(["%s"]*num)+");"
                me.cur.execute(insertstring,  vals)

                me.inscounter+=1 
                if me.inscounter % me.commit_every == 0 :
                        me.inscounter=0
                        me.dbclient.commit()

        
        @staticmethod
        def default_start_end(start, end):
            """
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            """
            if end is None: 
                endt = (datetime.date.today() + datetime.timedelta(days=1))
                end = endt.strftime("%Y-%m-%d")
            if start is None: 
                start = (datetime.datetime.strptime(end, "%Y-%m-%d") - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
            return start, end

        def get_count_per_categ(me, exp=None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the count of reports per category for a given period
            exp filter by experiment name (if None, don't filter) e.g. exp = "webs" => all experiments starting with webs (case insensitive)
            end = None, then end = end of today's day # looking at reported_at field!
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            start, end = ACDCExpDB.default_start_end(start, end)
            res = {}
            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 

            for table in me.tables: 
                dictcur.execute("select count(1) from %(table)s where (%(field)s < '%(end)s') and (%(field)s >= '%(start)s') %(expfilter)s;" %dict(table=(arch_prefix+table), field=field, end=end, start=start, expfilter = expfilter ))
                c = dictcur.fetchone()
                c = c.get('count')
                res[table] = c
            dictcur.close()
            return res

        def get_count_per_confidence(me, exp = None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the count of reports per confidence level for a given period; inside splited by report categories
            exp filter by experiment name (if None, don't filter) e.g. exp = "webs" => all experiments starting with webs (case insensitive)
            end = None, then end = end of today's day # looking at reported_at field!
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)
            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 

            for table in me.tables: 
                if table == 'botnet' :  # botnet does not have conf. level
                    continue
                dictcur.execute("select confidence_level, count(1) from %(table)s where (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s') %(expfilter)s group by confidence_level;" %dict(table=(arch_prefix+table), tsfield=field, end = end, start= start, expfilter=expfilter))
                c = dictcur.fetchall()
                """ like
                [(None, 299),
                 (6, 16),
                  (11, 357303),
                   (1, 798619),
                    (2, 761),
                     (3, 57208),
                      (7, 25434)]
                """
                for r in c: 
                    gid = str(r[0]) # confidence level 
                    if gid not in res: 
                        res[gid] = {'_sum' :  0}
                    res[gid][table] = r[1]
                    res[gid]["_sum"] += r[1]

            dictcur.close()
            return res

        def get_count_per_grp(me, grp, exp=None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the count of reports per group (partner, experiment, tool, ...) for a given period; inside splited by report categories
            exp = filter by experiment name... Does not make much sense for grp = 'experiment'
            end = None, then end = end of today's day # looking at reported_at field!
            grp is one of the helptables, e.g. experiments, tools, etc.
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            if grp not in me.helptables: 
                    log.error("Tried to get a non-existing entity. Should not have happened")
                    sys.exit(1)
            names = me.get_recs(grp) # get the list of all (id, name) for the "group"

            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)
            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 

            for table in me.tables: 
                dictcur.execute("select %(grp)s, count(1) from %(table)s where (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s') %(expfilter)s group by %(grp)s;" %dict(table=(arch_prefix+table), tsfield=field, end = end, start= start, grp = me.helptables[grp], expfilter= expfilter))

                c = dictcur.fetchall()
                """ like
                [(None, 299),
                 (6, 16),
                  (11, 357303),
                   (1, 798619),
                    (2, 761),
                     (3, 57208),
                      (7, 25434)]
                """
                for r in c: 
                    gid = str(r[0]) 
                    if gid not in res: 
                        res[gid] = {}
                    if 'name' not in res[gid] :
                        res[gid]['name'] = names[gid] if r[0] is not None else '--none--'
                    if 'data' not in res[gid]: 
                        res[gid]['data'] = {'_sum' :  0}
                    res[gid]['data'][table] = r[1]
                    res[gid]['data']["_sum"] += r[1]

            dictcur.close()
            return res

        def get_count_per_subcateg(me, grp, exp=None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the count of reports per subcategory for a given category(grp) for a given period; inside splited by report categories
            exp filter by experiment name
            end = None, then end = end of today's day # looking at reported_at field!
            grp is one of the tables, e.g. attack, malicious_uri, etc...
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            if grp not in me.tables: 
                    log.error("Tried to get a non-existing category. Should not have happened")
                    sys.exit(1)
            names = me.get_recs("report_subcategories") # get the list of all (id, name) for the "group"

            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)

            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 


            dictcur.execute(  "select report_subcategory as subc, count(1) from %(table)s where (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s') %(filtr)s group by subc;" %dict(table=(arch_prefix+grp), tsfield=field, end = end, start= start, filtr=expfilter))
            c = dictcur.fetchall()
            """ like
            [(None, 299),
             (6, 16),
              (11, 357303),
               (1, 798619),
                (2, 761),
                 (3, 57208),
                  (7, 25434)]
            """
            for r in c: 
                gid = str(r[0]) 
                name =  names[gid] if r[0] is not None else '--none--'
                res[name] = r[1]

            dictcur.close()
            return res

        def get_count_per_categ_between_partners(me, categ, exp=None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the count of reports per category/table(categ) for a given period; inside splited by partners who have records in partnerasn table 
            exp filter by experiment name
            end = None, then end = end of today's day # looking at reported_at field!
            categ is one of the tables, e.g. attack, malicious_uri, etc...
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            if categ not in me.tables: 
                    log.error("Tried to get a non-existing category. Should not have happened")
                    sys.exit(1)

            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)

            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 


            # select c, partners.partner from partners, (select count(1) as c, partnerasn.partner as p  from attack join partnerasn on partnerasn.asn = attack.meta_asn group by partnerasn.partner) as r where partners.Id = r.p;
            dictcur.execute(  "select  partners.partner, c from partners, (select count(1) as c, partnerasn.partner as p  from %(table)s join partnerasn on partnerasn.asn = %(table)s.meta_asn where (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s') %(filtr)s group by partnerasn.partner) as r where partners.Id = r.p;" %dict(table=(arch_prefix+categ), tsfield=field, end = end, start= start, filtr=expfilter))
            c = dictcur.fetchall()
            """ like
            [
               (7362 , TI-IT)
                (125486 , CERT-RO)
                   ( 434 , INCIBE)
                   (924 , CARNet)
                  (7808 , ISCTI)
                 (28 , DFN-CERT)
                                ]
                                but partner names go first

            """
            for r in c: 
                res[str(r[0])] = r[1]

            dictcur.close()
            return res

        def get_top_count(me, table, col, exp=None, n = 20, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the top "n" count of reports in a given table (e.g. 'attack') for a given period
            exp filter by experiment name
            end = None, then end = end of today's day # looking at 'field=reported_at' field!
            col is the field name per which we will count reports (group on that) , e.g. 'meta_asn'.
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            if table not in me.tables: 
                log.error("Tried to get a non-existing entity. Should not have happened")
                return None
            if col not in me.tables[table]:
                log.error("Tried to use a field that does not exist in the table! Should not have happened")
                return None


            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)
            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 

            # select count(1) as cnt, meta_asn as d from attack group by d order by cnt  desc limit 5;
            dictcur.execute("select %(col)s as col, count(1) as c from %(table)s where (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s') %(expfilter)s group by col order by c desc limit %(lim)s;" %dict(table=(arch_prefix+table), col = col, tsfield=field, end = end, start= start, lim = n, expfilter= expfilter))
            c = dictcur.fetchall()
            """ like
            [(None, 299),
             (6, 16),
                 (3, 57208),
                  (7, 25434)]
            """
            for r in c: 
                gid = (r[0]) 
                if gid is None: 
                    res['--none--'] = r[1]
                else:
                    res[str(gid)] = r[1]

            dictcur.close()
            return res


        def get_daily_diff_col(me, table, col, exp=None, start=None, end = None, field = 'reported_at', arch=False):
            """ 
            Returns the number of different values of column col in table table per day for a given period of time;
            exp filter by experiment name
            end = None, then end = end of today's day # looking at 'field=reported_at' field!
            col is the field name per which we will count reports (group on that) , e.g. 'meta_asn'.
            if start = None then start = end - 1 week
            end and start format are like '2015-02-05 00:00:00'; time part can be dropped = > 0:0:0
            if arch = True, looks in archive tables.
            """
            if table not in me.tables: 
                log.error("Tried to get a non-existing entity. Should not have happened")
                return None
            if col not in me.tables[table]:
                log.error("Tried to use a field that does not exist in the table! Should not have happened")
                return None


            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            start, end = ACDCExpDB.default_start_end(start, end)
            expfilter = get_exp_filter(exp) 
            arch_prefix = get_arch_prefix(arch) 
            

            # select count(1), r_at  from (select max(id), reported_at::date as r_at, source_value from malware where (reported_at >= '2015-02-14') and (reported_at < '2015-02-22') group by  source_value, r_at) as samples group by r_at order by r_at asc;
            dictcur.execute("select  r_at, count(1)  from (select reported_at::date as r_at, %(col)s as col from %(table)s where  (%(tsfield)s < '%(end)s') and (%(tsfield)s >= '%(start)s' %(expfilter)s ) group by col, r_at) as samples group by r_at order by r_at asc;" %dict(table=(arch_prefix+table), col = col, tsfield=field, end = end, start= start, expfilter=expfilter ))
            c = dictcur.fetchall()
            """ like
            [
              ( 2015-02-21, 839),
              ( 2015-02-20, 1212),
              ( 2015-02-19, 699)
                 ]
            """
            for r in c: 
                gid = (r[0]) 
                if gid is None: 
                    res['--none--'] = r[1]
                else:
                    res[str(gid)] = r[1]

            dictcur.close()
            return res


### OLD

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
         
        def close(me):
            if me.dbclient:
                me.dbclient.commit()
                me.dbclient.close()



                 

if __name__ == "__main__":
        import doctest
        doctest.testmod()

        db=ACDCExpDB(host='localhost', user='acdcuser', password='Uo9re0so', dbname= 'acdcexp')

        sys.exit(0)

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
        db.dbclient.commit()
