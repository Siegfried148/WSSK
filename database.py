#!/usr/bin/python
# -*- coding: utf-8 -*-
import sqlite3 as lite

descriptions = (
		(1,'ACTIVE ANALYSIS'),
		(2,'PASSIVE ANALYSIS'),
		(3,'HEARTBLEED ANALYSIS'),
		(4,'SHELLSHOCK ANALYSIS'),
		(5,'POODLE ANALYSIS'),
		(6,'DROWN ANALYSIS'),
		(7,'GHOST ANALYSIS'),
		)

con = lite.connect('/opt/wssk/db/wssk.db')
with con:
	cur = con.cursor()
        cur.execute("DROP TABLE IF EXISTS VISIT_IP")
	cur.execute("CREATE TABLE VISIT_IP(id INTEGER, ip TEXT, UNIQUE(ip), CONSTRAINT visit_ip_pk PRIMARY KEY (id))")

	cur.execute("DROP TABLE IF EXISTS CONSULTED_DOMAIN")
	cur.execute("CREATE TABLE CONSULTED_DOMAIN(id INTEGER, domain TEXT, UNIQUE(domain), CONSTRAINT consult_dom_pk PRIMARY KEY(id))")

	cur.execute("DROP TABLE IF EXISTS DESCRIPTION")
	cur.execute("CREATE TABLE DESCRIPTION(id INTEGER, description TEXT, CONSTRAINT description_pk PRIMARY KEY(id))")
	cur.executemany("INSERT INTO DESCRIPTION VALUES(?, ?)", descriptions)


	cur.execute("CREATE TABLE SEARCH(id INTEGER, visit_ip_id INT, consult_dom_id INT, description_id INT, date TEXT, FOREIGN KEY(visit_ip_id) REFERENCES VISIT_IP(id), FOREIGN KEY(consult_dom_id) REFERENCES CONSULTED_DOMAIN(id), FOREIGN KEY(description_id) REFERENCES DESCRIPTION(id))")
