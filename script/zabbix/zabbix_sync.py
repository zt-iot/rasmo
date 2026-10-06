#!/usr/bin/env python3

import time
import sys
import socket
import json
import psycopg2 as db
from psycopg2 import sql
from psycopg2.extras import execute_values
from zabbix_utils import ZabbixAPI
from pathlib import Path

# load API token
conf_path = Path('/var/lib/zabbix/blocklist.conf')
try:
	api_token = json.loads(conf_path.read_text())['token']
except Exception as error:
	print(f"Failed to load Zabbix API token: {error}", file=sys.stderr)
	raise

api = ZabbixAPI(url="localhost", token=api_token)

# host ID
host_id = sys.argv[1]
# function.value2: max(sync.cursor)
sync_cursor = sys.argv[2]
# function.value3: last(db.odbc.select)
odbc = sys.argv[3]
# event ID
event_id = sys.argv[4]


def close_event(event_id):
	# resolve the event
	api.event.acknowledge({ 'eventids': event_id, 'action': 2 })
	api.event.acknowledge({ 'eventids': event_id, 'action': 1 })

	# wait until problem is closed
	while api.problem.get({ 'eventids': event_id }):
		time.sleep(0.5)

with open("/tmp/zabbix-debug.txt", "w") as f:
	print(f"{sync_cursor}", file=f)

if not sync_cursor:
	sync_cursor = 0

# get data from db
table_name = 'global_ip_policies'
try:
	conn = db.connect("host=localhost dbname=zabbix user=zabbix")
except Exception as error:
	print('Failed to connect to Zabbix database', file=sys.stderr)
	raise

# need to guard length of the manualinput here
"""
sync_object = { "block":[], "unblock":[], "xid":"" }
manualinput_limit = 2047
ip_len = 20
xid_len = 20
keys_len = len(json.dumps(sync_object, separators=(',', ':')))
num_ipx = int((manualinput_limit - xid_len - keys_len) / ip_len)
"""
num_ipx = 100

with conn.cursor() as cursor:
	data_stmt = sql.SQL("""
		SELECT xid, ip, unblocked FROM {tab}
		WHERE %s::xid8 < xid AND xid <= %s::xid8
		ORDER BY xid ASC
		LIMIT %s;
	""").format(tab=sql.Identifier(table_name))

	try:
		cursor.execute(data_stmt, (sync_cursor, odbc, num_ipx + 1))
		# returns a list of tuples in ascending order: order matters because we need 
		# to sync from oldest to the newest, plus MANUALINPUT buffer length limit,
		# need to limit number of rows to read

		# *IMPORTANT*: as we rely on xid instead of tracking individual rows,
		# the rows added by the same transaction must not be divided into separate messages;
		# therefore we fetch num_ipx + 1 rows, if the last row has the same xid as the {num_ipx}-th,
		# then the rows with the same xid should all be deferred to the next sync session
		# A transaction is not allowed to have more than {num_ipx} rows, restricted by the receiver.
		data = cursor.fetchall()

		# the rest of the rows will be synced in the next session, as trigger fires
		# whenever new data arrives at the item or at 30s interval if nodata() is used,
		# sync will start again when device acks the current message

		# psycopg2 opens transaction for SELECT too
		conn.rollback()
	except (Exception, db.DatabaseError) as error:
		print(f"Failed to retrieve data from {table_name}: {error}", file=sys.stderr)
		conn.rollback()
		raise

conn.close()

if not data:
	close_event(event_id)
	sys.exit(0)

# format data and push to the device
# data is a list of tuples, e.g., ('11377912', '192.168.0.1', False)

if len(data) <= num_ipx:
	xid_bound = None
else:
	xid_bound = int(data[-1][0]) # string needs to be converted

# build sync_object
blocklist = []
unblocklist = []
xidlist = []
message = {}
for record in data:
	xid = int(record[0])
	if xid == xid_bound:
		break

	ip = record[1]
	op = record[2]
	if op is True:
		unblocklist.append(ip)
	elif op is False:
		blocklist.append(ip)
	xidlist.append(xid)

if blocklist:
	message["block"] = blocklist
if unblocklist:
	message["unblock"] = unblocklist
if xidlist:
	message["xid"] = str(max(xidlist))

# tell agent to publish
script_name = 'publish-agent'
script_id = api.script.get({ 'search': { 'name': script_name} })[0].get('scriptid')

if message:
	resp = api.script.execute({ 'scriptid': script_id, 'hostid': host_id,
		'manualinput': json.dumps(message, separators=(',', ':')) })

close_event(event_id)
