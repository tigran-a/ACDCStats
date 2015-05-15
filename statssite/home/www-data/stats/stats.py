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

from flask import Flask, Blueprint
import flask
import ddata
import frontpage
app = Flask(__name__)

app.register_blueprint(ddata.databp, url_prefix='/data')
app.register_blueprint(frontpage.fpbp, url_prefix='/stats')


if __name__  =='__main__':
    print(app.url_map)
    app.run(debug=True)
