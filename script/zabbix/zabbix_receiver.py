#!/usr/bin/env python3

import re
import sys
import time
import socket
import ipaddress
import psycopg2 as db
from psycopg2 import sql
from psycopg2.extras import execute_values
import json
from zabbix_utils import ZabbixAPI
from pathlib import Path

'''
./zabbix_server.py <hostid> <item_name> <item_id> <trigger_id> <event_id>
'''
# load API token
conf_path = Path('/var/lib/zabbix/blocklist.conf')
try:
	api_token = json.loads(conf_path.read_text())['token']
except Exception as error:
	print(f"Failed to load Zabbix API token: {error}", file=sys.stderr)
	raise

api = ZabbixAPI(url="localhost", token=api_token)

# get host ID
hostid = sys.argv[1]

# receiver
item_name = sys.argv[2]
item_id = sys.argv[3]

# event ID
ssh_event_id = sys.argv[4]

# timestamp trapper item 
cursor_items = api.item.get({'hostids': hostid, 'search': { 'name': item_name + 'Cursor' }})
cursor_id = cursor_items[0].get('itemid')
#api.history.clear(cursor_id)

# COMMIT and ROLLBACK managed by python context manager
# entries: iterable of tuple (ip, unblocked)
def db_entry_update(conn, table_name, entries, dev_xid):
	stmt = sql.SQL("""
		INSERT INTO {tab} (ip, unblocked) VALUES %s
		ON CONFLICT (ip) DO UPDATE SET
			unblocked = EXCLUDED.unblocked,
			xid = pg_current_xact_id(),
			ts = CURRENT_TIMESTAMP
		WHERE {tab}.unblocked = TRUE AND {tab}.xid <= {xid}::xid8;
	""").format(tab=sql.Identifier(table_name), xid=sql.Literal(dev_xid))

	# connect to the database
	try:
		with conn.cursor() as cursor:
			# page_size default 100
			execute_values(cursor, stmt, entries, template="(%s, %s)")
	except (Exception, db.DatabaseError) as error:
		print('Failed to insert into Zabbix database', file=sys.stderr)
		conn.rollback()
		raise

def close_event(event_id):
	# resolve the event
	api.event.acknowledge({ 'eventids': event_id, 'action': 2 })
	api.event.acknowledge({ 'eventids': event_id, 'action': 1 })

	# wait until problem is closed
	while api.problem.get({ 'eventids': event_id }):
		time.sleep(0.5)

try:
	conn = db.connect("host=localhost dbname=zabbix user=zabbix")
except Exception as error:
	print('Failed to connect to Zabbix database', file=sys.stderr)
	raise

# time when the event is raised
event_st_clock = api.event.get({ 'eventids': ssh_event_id })[0].get('clock')

# get last processed timestamp
last_ts = api.item.get({ 'itemids': cursor_id })[0].get('lastvalue')

# if no last processed timestamp, process from the beginning?
if last_ts == '':
	start_clock = '0'
	start_ns = '0'.zfill(9)
else:
	ts_list = last_ts.split('.')
	start_clock = ts_list[0]
	if len(ts_list) == 1:
		start_ns = '0'.zfill(9)
	else:
		start_ns = ts_list[1].zfill(9)

# value of the receiver cursor
history_start_ts = '.'.join([start_clock, start_ns])
row_timestamp = history_start_ts
starting_ts = history_start_ts

table_name = "global_ip_policies"
num_ipx = 100

# {num_ipx} rows per transaction
while True:
	# must specify history level or it returns empty history
	# history.get() can only filter from 'clock', not 'ns'
	ssh_logs = api.history.get({'history': 4, 'itemids': item_id,
								'time_from': start_clock, 'sortfield': [ 'clock', 'ns' ],
								'sortorder': 'ASC' })
	if not ssh_logs:
		break

	# process each log of the item
	# result example: { "itemid": "23296", "clock": "1351090996", "value": "0.085", "ns": "563157632"},
	for row in ssh_logs:
		row_clock = row.get('clock')
		row_ns = row.get('ns').zfill(9)
		row_timestamp = '.'.join([row_clock, row_ns])

		# time_from only by seconds, need to skip entries that have lower ns
		if row_timestamp <= history_start_ts:
			continue

		# value example: {"block":["ip1", "ip2"],"xid":"123"}
		value = row.get('value')
		try:
			obj = json.loads(value)
			xid = obj['xid']
			blocked_ip = obj['block']
		except (json.JSONDecodeError, KeyError) as error:
			print(f"Failed to parse {value}: {error}", file=sys.stderr)
			raise

		# verify block values
		for ip in blocked_ip:
			try:
				ipaddress.ip_address(ip)
			except ValueError:
				raise ValueError(f"Invalid block value: {ip!r}")

		# verify xid value
		if not re.fullmatch(r'[0-9]{1,20}', xid):
			raise ValueError(f"Invalid xid: {xid!r}")
			
		# get block entries and xid
		entries = []
		for ip in blocked_ip:
			entries.append((ip, False))

			if len(entries) == num_ipx:
				# if reached the limit, commit existing entires and 
				# start a new batch
				db_entry_update(conn, table_name, entries, xid)
				conn.commit()
				entries = []

		# insert data into the global_blocklist table
		if entries:
			db_entry_update(conn, table_name, entries, xid)
			conn.commit()

	# break if timestamp is the same or time has passed
	if history_start_ts == row_timestamp or (int(row_clock) - int(event_st_clock)) >= 30:
		break
	else:
		start_clock = row_clock
		start_ns = row_ns
		history_start_ts = row_timestamp

# close DB connection
conn.close()

# update timestamp of last processed data
if row_timestamp > starting_ts:
	api.history.push({ 'itemid': cursor_id, 'value': row_timestamp })

# finalize
close_event(ssh_event_id)
