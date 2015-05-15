#!/usr/bin/env python3

"""
Script creating archive tables and moving the data from non-archive tables to these archive tables. 
(for example, all records that are older than 8 days are moved to archive tables)

Note: might be not needed

Requires: 
pip3 install psycopg2
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
log.setLevel(logging.DEBUG)
loggerfilehandler = logging.FileHandler('/var/log/postgreslib-backup.log')
loggerfilehandler.setLevel(logging.DEBUG)
# create console handler with a higher log level
loggerconsolehandler = logging.StreamHandler()
#loggerconsolehandler.setLevel(logging.ERROR)
loggerconsolehandler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
loggerfilehandler.setFormatter(formatter)
loggerconsolehandler.setFormatter(formatter)
# add the handlers to the logger
log.addHandler(loggerfilehandler)
log.addHandler(loggerconsolehandler)


import re
import dateutil.parser
import datetime


def i_dont_read_personal_data(ip):
        #keep 2 first blocks only
        return ":".join(( ".".join(ip.split(".")[:2]) ).split(':')[:2])
        

class ACDCExpDBBackup:

        # a regexp to extract experiment, tool, partner
        # 
        headerexp = re.compile("\s*\[(.*?)\]\s*\[(.*?)\]\s*\[(.*?)\](.*)")

        # if these keys appear in report, they will be stripped, if the corresponding option is set
        keys_to_strip = ['sample_b64']
        new_value_for_stripped = 'stripped'

        def __init__(me, dbname, user, password, host='localhost', port=5432,rewrite = False, ensure_tables = True, commit_every = 100):
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


            # makeing tables prefixed with arch_
            keyz= list(me.tables.keys())
            for k in keyz: 
                me.tables["arch_"+k] = me.tables.pop(k)


            if ensure_tables: 
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
                #for t in me.tables:
                #        for idx in generic_indexes:
                #                # botnet does not have timestamp field
                #                try:
                #                        cur.execute("Create index idx_%s_%s on %s(%s);"%(t,idx,t,idx))
                #                        log.info('Index created in table %s for field %s', t, idx)
                #                except Exception as e:
                #                   log.warning('Could not create index : %s', e) 
                #                finally: 
                #                   me.dbclient.commit()
                try:
                        cur.execute("Create index idx_arch_malware_ts_samples on arch_malware(ts, source_value);") # note! source_key is always "malware" in spec...
                        log.info('Index created in table arch_malware for fields ts and source_value')
                except Exception as e:
                   log.warning('Could not create index : %s', e) 
                finally: 
                   me.dbclient.commit()

                try:
                        cur.execute("Create index idx_arch_malware_ts_samples on arch_malware(ts, mime_type);") 
                        log.info('Index created in table arch_malware for fields ts and mime_type')
                except Exception as e:
                   log.warning('Could not create index : %s', e) 
                finally: 
                   me.dbclient.commit()
                
            me.dbclient.commit()
  

            if rewrite: 
                raise NotImplementedError
                    #if dbname in me.dbclient.database_names():
                    #        me.dbclient.drop_database(dbname)



        
        @staticmethod
        def __parse_exp(report):
                if report is None: 
                    log.warning("No report_type found! ")
                # e.g. "report_type": "[DDOS][HONEYNET][TID] Login attack by TI+D Kippo honeypot report"
                m = ACDCExpDBBackup.headerexp.match(report)
                res = {}
                if m is None: 
                    log.warning("Could not determine experiment, tool and partner from report_type")
                else: 
                    res['experiment'], res['tool'], res['partner'], *desc = m.groups()

                return  res


        
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
                start = (endt - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
            return start, end

        def arch_old_data(me, oldness = 8, field = 'reported_at'):
            """ 
            moves data from table to arch_table which is older (wrt field field) than oldness days 
            """
            me.cur.execute("analyze;")

            dictcur = me.dbclient.cursor(cursor_factory=psycopg2.extras.DictCursor)
            res = {}
            condition =  field + " < (now() - INTERVAL '%s"%(oldness) +" days')::date"
            for t in db.tables:
                origtable = t[5:]
                log.info("")
                log.info(t + "\n" + 42*"-")
                move = "insert into %(archtable)s ("%(dict(archtable=t))  + ",".join(db.tables[t].keys()) +") select " + ",".join(db.tables[t].keys()) + " from " + origtable + " where " + condition + ";"
                log.info(move)
                dictcur.execute(move)
                log.info("")
                delete = "delete from %s"%(origtable) + " where " + condition +";"
                log.info(delete)
                dictcur.execute(delete)
                me.dbclient.commit()
                #dictcur.execute("select count(1) from %s where (%s < '%s') and (%s >= '%s');" %(table, field, end, field, start ))
                #c = dictcur.fetchone()
                #c = c.get('count')
                #res[table] = c
            dictcur.close()
            me.cur.execute("analyze;")
            return res




                 

if __name__ == "__main__":
        import doctest
        doctest.testmod()

        db=ACDCExpDBBackup(host='localhost', user='acdcuser', password='Uo9re0so', dbname= 'acdcexp', ensure_tables= False)
        db.arch_old_data(oldness=7);


        sys.exit(0)

        db.dbclient.commit()
