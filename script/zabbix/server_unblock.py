#!/usr/bin/env python3

import sys
import ipaddress
import psycopg2 as db
from psycopg2 import sql

def unblock_ip(conn, table_name, ip):
	stmt = sql.SQL("""
			UPDATE {tab}
			SET unblocked = TRUE,
				xid = pg_current_xact_id(),
				ts = CURRENT_TIMESTAMP
			WHERE ip = %s;
		""").format(tab=sql.Identifier(table_name))
	with conn.cursor() as cursor:
		try:
			cursor.execute(stmt, (ip,))
			conn.commit()
		except Exception as error:
			print(f"Failed to update {ip} in table {table_name}", file=sys.stderr)
			conn.rollback()
			raise

ip = sys.argv[1]
try:
	ipaddress.ip_address(ip)
except ValueError:
	raise ValueError(f"Invalid IP address {ip!r}")

try:
	conn = db.connect("host=localhost dbname=zabbix user=zabbix")
except Exception as error:
	print('Failed to connect to Zabbix database', file=sys.stderr)
	raise

unblock_ip(conn, "global_ip_policies", ip)
conn.close()
