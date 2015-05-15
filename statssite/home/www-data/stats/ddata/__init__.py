#!/usr/bin/env python3 
"""
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

from flask import Flask, Blueprint, jsonify, request
import flask
from datetime import datetime,timedelta


# connecting to the DB:
import ddata.postgreslib
import re
dbexp = postgreslib.ACDCExpDB(host='localhost', user='acdcuser', password='Uo9re0so', dbname= 'acdcexp')


def only_alphanum(s):
    if s is not None: 
        return re.sub(r'\W+', '', s)
    else:
        return None

def ensure_date(s):
    """YYYY-MM-DD"""
    if s is None: 
        return None
    try:
        datetime.strptime(s, '%Y-%m-%d')
        return s
    except ValueError:
        return None
    
def extract_params(req):
    res = {}
    res['start'] = ensure_date(req.args.get('start', None))
    res['end'] = ensure_date(req.args.get('end', None))
    res['arch'] = req.args.get('arch', False)
    return res

databp = Blueprint('ddata', __name__, template_folder="templ")

@databp.route('/')
@databp.route('/x')
def hello_world():
    res = extract_params(request)
    res['msg'] = 'test'
    res['url'] = request.url
    return jsonify(res = res) 



@databp.route('/categ')
@databp.route('/categ/<exp>')
def categ_count(exp=None):
    exp = only_alphanum(exp)
    parms = extract_params(request)
    return jsonify(res = dbexp.get_count_per_categ(exp=exp, **parms)) # 1 week by default


@databp.route('/exp2')
@databp.route('/exp2/<exp>')
def exp2_count(exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_count_per_grp('experiments', exp=only_alphanum(exp), **parms)) # 1 week

@databp.route('/tool2')
@databp.route('/tool2/<exp>')
def tool2_count(exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_count_per_grp('tools', exp=only_alphanum(exp), **parms)) # 1 week

@databp.route('/partner2')
@databp.route('/partner2/<exp>')
def partner2_count(exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_count_per_grp('partners', exp=only_alphanum(exp), **parms)) # 1 week

@databp.route('/confidence2')
@databp.route('/confidence2/<exp>')
def confidence2_count(exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_count_per_confidence(exp=only_alphanum(exp), **parms)) # 1 week

#@databp.route('/attack_subcateg')
#def attack_subcateg_count():
#    return jsonify(res = dbexp.get_count_per_subcateg("attack")) # 1 week

@databp.route('/<tbl>_subcateg')
@databp.route('/subcateg/<tbl>')
@databp.route('/subcateg/<tbl>/<exp>')
def tbl_subcateg_count(tbl, exp=None):
    parms = extract_params(request)
    if tbl in ['attack','bot','botnet','c2_server','malicious_uri','spam_campaign']:
        return jsonify(res = dbexp.get_count_per_subcateg(tbl, exp=only_alphanum(exp), **parms)) # 1 week
    else:
        return jsonify(res = None)

@databp.route('/concerned/<tbl>')
@databp.route('/concerned/<tbl>/<exp>')
def concerned(tbl, exp=None):
    parms = extract_params(request)
    if tbl in ['attack','bot','botnet','c2_server','malicious_uri','spam_campaign','malware', 'vulnerable_uri', 'fast_flux']:
        return jsonify(res = dbexp.get_count_per_categ_between_partners(tbl, exp=only_alphanum(exp), **parms)) # 1 week
    else:
        return jsonify(res = None)

@databp.route('/top_asn_attacks')
@databp.route('/top_asn_attacks/<exp>')
def top_asn_attacks(exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_top_count(table="attack", col ="meta_asn", n = 20, exp=only_alphanum(exp), **parms)) # 1 week

@databp.route('/distinct_malware')
@databp.route('/distinct_malware/<exp>')
def distinct_malware(exp=None):
    #db.get_daily_diff_col("malware", "source_value")
    parms = extract_params(request)
    return jsonify(res = dbexp.get_daily_diff_col(table="malware", col ="source_value", exp=only_alphanum(exp), **parms)) # 1 week

@databp.route('/top/<categ>/<fld>')
@databp.route('/top/<categ>/<fld>/<exp>')
def top(categ, fld, exp=None):
    parms = extract_params(request)
    return jsonify(res = dbexp.get_top_count(table=categ, col = fld, exp=only_alphanum(exp), n = 20, **parms)) # 1 week

"""
@databp.route('/report_dynamics/<int:_from>/<int:_to>')
@databp.route('/report_dynamics')
def global_dynamics_by_day(_from = None, _to = None):
    if _to is None:
        _to = datetime.now()
    else:
        _to = datetime.strptime(str(_to), "%Y%m%D")
    if _from is None:
        _from = _to - timedelta(days=30)
    else:
        _from = datetime.strptime(str(_from), "%Y%m%D")
    # ensuring beginning of the day
    _from = datetime(_from.year, _from.month, _from.day)
    return jsonify(res = dbexp.get_dynamics_by_day(_from, _to))
"""
