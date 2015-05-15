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

from flask import Flask, Blueprint, request
import flask
import urllib

fpbp  = Blueprint('frontpage', __name__, template_folder="templ")

def get_param_str():
    res = urllib.parse.urlencode(request.args)
    if res != "":
        return "?"+res
    else:
        return res



@fpbp.route('/')
@fpbp.route('/overview')
def overview():
    return flask.render_template('overview.html', parm = get_param_str())

@fpbp.route('/graph')
@fpbp.route('/graph/')
@fpbp.route('/graph/<exp>')
def g1(exp=None):
    return flask.render_template('graphs.html', exp=exp, parm = get_param_str())


@fpbp.route('/attack')
@fpbp.route('/attack/')
@fpbp.route('/attack/<exp>')
def attack(exp=None):
    return flask.render_template('attack.html', exp=exp, parm = get_param_str())
@fpbp.route('/bot')
@fpbp.route('/bot/')
@fpbp.route('/bot/<exp>')
def bot(exp=None):
    return flask.render_template('bot.html', exp=exp, parm = get_param_str())
@fpbp.route('/botnet')
@fpbp.route('/botnet/')
@fpbp.route('/botnet/<exp>')
def botnet(exp=None):
    return flask.render_template('botnet.html', exp=exp, parm=get_param_str())
@fpbp.route('/c2_server')
@fpbp.route('/c2_server/')
@fpbp.route('/c2_server/<exp>')
def c2_server(exp=None):
    return flask.render_template('c2_server.html', exp = exp, parm = get_param_str())
@fpbp.route('/malware')
@fpbp.route('/malware/')
@fpbp.route('/malware/<exp>')
def malware(exp=None):
    return flask.render_template('malware.html', exp=exp, parm=get_param_str())
@fpbp.route('/malicious_uri')
@fpbp.route('/malicious_uri/')
@fpbp.route('/malicious_uri/<exp>')
def malicious_uri(exp=None):
    return flask.render_template('malicious_uri.html', exp=exp, parm=get_param_str())
@fpbp.route('/spam_campaign')
@fpbp.route('/spam_campaign/')
@fpbp.route('/spam_campaign/<exp>')
def spam_campaign(exp=None):
    return flask.render_template('spam_campaign.html', exp=exp, parm = get_param_str())


@fpbp.route('/fast_flux')
@fpbp.route('/fast_flux/')
@fpbp.route('/fast_flux/<exp>')
def fast_flux(exp=None):
    return flask.render_template('fast_flux.html', exp=exp, parm = get_param_str())

@fpbp.route('/vulnerable_uri')
@fpbp.route('/vulnerable_uri/')
@fpbp.route('/vulnerable_uri/<exp>')
def vulnerable_uri(exp=None):
    return flask.render_template('vulnerable_uri.html', exp=exp, parm = get_param_str())

@fpbp.route('/tops')
@fpbp.route('/tops/')
@fpbp.route('/tops/<exp>')
def tops(exp=None):
    return flask.render_template('tops.html', exp=exp, parm = get_param_str())



@fpbp.route('/ddos')
def ddos():
    return flask.render_template('ddos.html')
