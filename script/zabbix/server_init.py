#!/usr/bin/env python3

import time
import sys
import psycopg2 as db
from psycopg2 import sql
import socket

try:
	conn = db.connect("host=localhost dbname=zabbix user=zabbix")
except Exception as error:
	print('Failed to connect to Zabbix database', file=sys.stderr)
	raise

# create table
def db_create_table(conn, table_name):
	stmt = sql.SQL("""
				CREATE TABLE IF NOT EXISTS {tab} (
				    xid       xid8 NOT NULL DEFAULT pg_current_xact_id(),
				    ts        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
				    ip        inet PRIMARY KEY,
				    unblocked boolean NOT NULL DEFAULT FALSE
				);
			""").format(tab=sql.Identifier(table_name))
	# create if table does not exist
	with conn.cursor() as cursor:
		try:
			cursor.execute(stmt)
			conn.commit()
		except Exception as error:
			print(f"Failed to create table {table_name}: {error}", file=sys.stderr)
			conn.rollback()
			raise

db_create_table(conn, "global_ip_policies")
conn.close()
