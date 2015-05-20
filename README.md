# ACDCStats
Retrieve, store, compute and display via web the statistics on security reports from [ACDC](http://acdc-project.eu) CCH (see the [community portal](http://communityportal.acdc-project.eu)). This code is currently running at https://acdc.uni.lu.

Two main components are:

1. `watcher`, which is a xmpp client fetching the reports and using `postgreslib` to parse and write it to the postgresql database
2. `statssite`, is a web interface to display the needed graphs; the values are calculated in the time of request (no precalculation) 
    again using `postgreslib` module. 

## Set up and run ##

We suppose here a server running some recenv version of Debian-based Linux distributions.

### Database ###
The current version of the software is using [PostgreSQL](http://www.postgresql.org/).

#### Installation ###
```sh
$ sudo apt-get install postgresql libpq-dev
```

#### Connecting ####

```sh
$ sudo su - postgres
$ psql
```

#### Creating user/database ####

```sql
 CREATE USER acdcuser WITH PASSWORD 'Uo9re0so';
 create database acdcexp;
 GRANT ALL PRIVILEGES ON DATABASE acdcexp to acdcuser ;
```

Exit `Ctrl+D`, and return from postgres user `Ctrl+D`

#### Allowing to connect ####

```sh
$ sudo echo "host   acdcexp acdcuser        127.0.0.1/24    md5" >> /etc/postgresql/9.4/main/pg_hba.conf
```

#### Test connection ####

```sh
$ psql acdcexp acdcuser
```
[TODO: check] 


### Watcher ### 

I's an xmpp client which writes the ACDC reports to the database

#### Dependencies #### 

```sh
$ sudo apt-get install python3 python3-pip python3-dateutil
$ sudo pip3 install psycopg2 
$ sudo pip3 install sleekxmpp
```

#### Configuration ####

In the `xmppclient.py` one must change 

```python
KEY_ID = 111
KEY = "11111111111111111111111111111111"
```

to yours CCH key_id and key.

Also, if you used other user/password for the database, don't forget to modify this line: 

```python
xmpp.set_postgres(host='localhost', user='acdcuser', password='Uo9re0so', dbname= 'acdcexp', commit_every=100)
```

#### Running ####

(supposing you are in the `watcher` directory):

```sh
$ ./xmppclient.py
```

After every 100 messages received, it will report some message. Loglevel, log file name (note, it outputs both to the console and the log file), 
magic number 100 and other things can be changed in `xmppclient.py`. 

Now messages should go to the database. 

### Website ###

We used [nginx](http://nginx.org), [uWSGI](https://uwsgi-docs.readthedocs.org/en/latest/) and [flask](http://flask.pocoo.org/) python framework


#### Installation ####

```sh
$ sudo pip3 install Flask psycopg2
$ sudo apt-get install nginx uwsgi uwsgi-plugin-python3
```

#### Configuration ####

Some configuration files are given in `statssite/etc` (to be put to your `/etc` directory)

We suppose that the home directory of `www-data` user is in `/home/www-data`. 
Then you need put the files from `statssite/home/www-data` into your `/home/www-data`;
adapt the server names everywhere if needed nad  then restart `uwsgi` and `nginx` services: 

```sh
$ sudo service uwsgi restart
$ sudo service nginx restart
```


## TODO ##

Actually test what is written in README.md

## Improvements ##

Since every time the site requests the database for a given period, it makes sense to precalculate the results of some queries and 
simply adjust these with the latest values which will lead to the significant improvement in the performance. 
