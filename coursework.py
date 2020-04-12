from flask import Flask, abort, request, jsonify, g
import requests
from cassandra.cluster import Cluster
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
import datetime
import ssl
from flask_marshmallow import Marshmallow

## setting a contact to Cassandra cluster and opening a session for read/write operations

cluster = Cluster(contact_points=['172.17.0.2'], port=9042)
session = cluster.connect()

## preparing the context for SSL connections and loading the certificate and key for self-signed certificate

ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
ctx.load_cert_chain('certs/domain.crt', 'certs/domain.key')

## creating an authentication context

auth = HTTPBasicAuth()

## creating an application context and wrapping it with object serialisation context for later use of HATEOAS

app = Flask(__name__)
ma = Marshmallow(app)

## setting url template for API request

pub_token = 'pk_5a801069fa8548e88ba6b909a9234be7'
quote_url_template = 'https://cloud.iexapis.com/v1/stock/{quote}/quote?token={token}'

## setting template for HATEOAS response

class UserSchema(ma.Schema):
	class Meta:
		fields = ('username', 'action', '_links')
		# fields to be serialised and returned as a response
	_links = ma.Hyperlinks({'self': ma.URLFor('get_user', username='<username>')})
	# get_user is a url endpoint which is defined later
	# URLFor takes an argument of url endpoint and other arguments as needed in that endpoint

user_schema = UserSchema()

## landing page for testing the connection

@app.route('/')
def landing():
	name = request.args.get('name', 'World')
	return '<h1>Hello, {}!</h1>'.format(name)

## process for verifying password during authentication

@auth.verify_password
def verify_password(username, password):
	if username and password:
		# check if there are both username and password provided
		curr_user = username
		rows = session.execute("""SELECT * from portfolio.users where username='{}'""".format(curr_user))
		# query a result from users table in the database, using the username provided as a filter in query
		if rows[0].username is not None:
			# if the result is not None, which means that there is a user registered in the database
			if pwd_context.verify(password, rows[0].password_hash):
				# check if the password provided is correct or not, by comparing equivalency of both hash values
				g.user = curr_user
				# if the password is correct, set the username attribute to global object for later use
				return True
	return False
	# if any condition is not met, do not let it be verified
	# 401 Unauthorised response is returned if the authentication process is cancelled

## endpoint for creating new user

@app.route('/users', methods=['POST'])
def create_user():
	if (not request.json) or (not 'username' in request.json) or (not 'password' in request.json):
		# check if the request is in JSON format and if there are both username and password provided in the request
		abort(400)
		# if not, return 400 Bad Request response
	username = request.json['username']
	password = request.json['password']
	# get username and password from the request
	rows = session.execute("""SELECT * from portfolio.users where username='{}'""".format(username))
	# query a result from users table in the database, using the username provided as a filter in query
	if len(rows.all())>0:
		# if the length of result is more than zero, which means that the requested username is already existed
		abort(400)
		# return 400 Bad Request response to let the user choose another username
	password_hash = pwd_context.encrypt(password)
	# encrypt the provided password into a hash
	session.execute("""INSERT INTO portfolio.users(username, password_hash) VALUES('{}','{}')""".format(username, password_hash))
	# store username and password hash to the database
	return user_schema.dump({'username': username, 'action': 'created'}), 201
	# return HATEOAS-201 Created response to let the user know where to find the resource 

## endpoint for getting user information

@app.route('/users/<username>', methods=['GET']) # OK
def get_user(username):
	try:
		curr_username = request.args.get('username',str(username))
		# get username from the request
		rows = session.execute("""SELECT * from portfolio.users where username='{}'""".format(curr_username))
		# query a result from users table in the database, using the username provided as a filter in query
		curr_username = rows[0].username
		# get only username from the query result
		return user_schema.dump({"username": curr_username, 'action': 'read'}), 200
		# return HATEOAS-200 OK response to let the user know where to find the resource
	except:
		abort(404)
		# if username is not found in the database, return 404 Not Found response

## endpoint for updating password

@app.route('/users', methods=['PUT'])
@auth.login_required
# in order to update new password, the user must specify a correct initial password first
# therefore, an authentication is required and this endpoint is reachable only if the user is verified
def update_password():
	try:
		new_password = request.json['new_password']
		# get neww password from the request
		password_hash = pwd_context.encrypt(new_password)
		# encrypt the provided new password into a hash
		rows = session.execute("""UPDATE portfolio.users SET password_hash = '{}' where username='{}'""".format(password_hash, g.user))
		# update new password to a designated row, using the username provided in an authentication process as a filter in query
		return user_schema.dump({"username": g.user, 'action': 'updated'}), 200
		# return HATEOAS-200 OK response to let the user know where to find the resource
	except:
		abort(400)
		# if there is any error in the try clause, return 400 Bad Request response

## endpoint for deleting user

@app.route('/users', methods=['DELETE'])
@auth.login_required
# the user must be authenticated in order to delete his own account
# no user is allowed to delete other accounts which are not his own
def delete_user():
	session.execute("""DELETE from portfolio.users where username='{}'""".format(g.user))
	# delete a designated row, using the username provided in an authentication process as a filter in query
	return user_schema.dump({"username": g.user, 'action': 'deleted'}), 200
	# return HATEOAS-200 OK response to let the user know the location of deleted resource

## endpoint for getting price information of chosen stock

@app.route('/price-info/<quote>', methods=['GET'])
def show_price(quote):
	quote_use = request.args.get('quote',str(quote))
	# get stock quote form the request
	quote_url = quote_url_template.format(quote=quote_use, token=pub_token)
	# provide the stock quote and necessary token to the url template for API request
	resp = requests.get(quote_url)
	# send API request
	if resp.ok:
		# if the request does not troubleshoot any error
		resp_json = resp.json()
		# transform the returned resource to JSON format
		return jsonify({'symbol': resp_json["symbol"], 'latestPrice': resp_json["latestPrice"], 'priceref': resp_json["latestTime"]}), 200
		# return 200 OK response with price information
	else:
		return resp.reason
		# if the requrest shows a sign of error, return the reason of it

## endpoint for getting portfolio status of current user

@app.route('/status-port', methods=['GET'])
@auth.login_required
# since financial information should be confidential, the authentication process is required
def status_port():
	rows = session.execute("""SELECT * from portfolio.transactions where username='{}'""".format(g.user))
	# query a result from transactions table in the database, using the username provided as a filter in query
	total_buy = 0
	total_sell = 0
	for transaction in rows:
		if transaction.action=='buy':
			total_buy += float(transaction.value)*int(transaction.volume)
		elif transaction.action=='sell':
			total_sell += float(transaction.value)*int(transaction.volume)
	# for each transaction, determine if it is a buy or sell, then accumulate the values
	net_value = total_buy-total_sell
	# the net value of all transactions is determined by sum value of buy minus sum value of sell
	if net_value >= 0:
		stance = "long"
	else:
		stance = "short"
	# if the net value is positive, then the overall stance of portfolio is a long
	# if not, then it is a short

	return jsonify({"username": g.user, "stance": stance, "netValue": net_value}), 200
	# return 200 OK response with status summary

## endpoint for creating transaction to the portfolio

@app.route('/action-port', methods=['POST'])
@auth.login_required
# since the financial transaction should only be done by the beneficiary, the authentication process is required
def action_port():
	quote = request.json['quote']
	action = request.json['action']
	volume = request.json['volume']
	# get stock quote, action and volume of transaction from the request
	quote_url = quote_url_template.format(quote=quote, token=pub_token)
	# provide the stock quote and necessary token to the url template for API request
	resp = requests.get(quote_url)
	# send API request
	if resp.ok:
		# if the request does not troubleshoot any error
		resp_json = resp.json()
		# transform the returned resource to JSON format
		t = datetime.datetime.now()
		# get current timestamp
		s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
		# change it to desirable format
		session.execute("""INSERT INTO portfolio.transactions(username, quote, action, value, volume, priceref, transactionTime) VALUES('{}','{}','{}',{},{},'{}','{}')""".format(str(g.user), str(quote), str(action), float(resp_json["latestPrice"]), int(volume), str(resp_json["latestTime"]), str(s[:-3])))
		# insert all necessary transaction information into the database
		return 'username: {}, quote: {}, action: {}, value: {}, volume: {}, priceref: {}, transactionTime: {}'.format(g.user, quote, action, resp_json["latestPrice"], volume, resp_json["latestTime"], s[:-3]), 201
		# return 201 Created response
	else:
		return resp.reason
		# if the requrest shows a sign of error, return the reason of it

if __name__=="__main__":
	app.run(host='0.0.0.0', port=443, ssl_context=ctx)



