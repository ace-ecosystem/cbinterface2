#!/usr/bin/env python3

import sqlite3
import pandas as pd
import argparse
import sys
import os

parser = argparse.ArgumentParser()
parser.add_argument("history_file", help="Path to Chromium based sqlite history file.")
args = parser.parse_args()

if os.path.exists(args.history_file):
    None
else:
    print("[ERROR] file does not exist.")
    sys.exit(1)

db = sqlite3.connect(args.history_file)
c = db.cursor()

tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table'", db)
tables = list(tables["name"])

browser = "chromium"
if "chrome" in args.history_file.lower():
    browser = "chrome"
elif "edge" in args.history_file.lower():
    browser = "edge"

host = "_unknown_host"
if "_" in args.history_file:
    host = args.history_file[: args.history_file.find("_")]
part_dir = f"{host}_{browser}_raw_csv_tables"
if not os.path.exists(part_dir):
    os.mkdir(part_dir)

for table in tables:
    try:
        data = pd.read_sql_query(f"SELECT * FROM {table}", db)
        data.to_csv(f"{part_dir}/{browser}_history_{table}.csv")
        if os.path.exists(f"{part_dir}/{browser}_history_{table}.csv"):
            print(f" + WROTE: {part_dir}/{browser}_history_{table}.csv")
    except Exception as e:
        print(f"[WARN] problem selecting from table={table}: {e}")

# Try to make it more human readable
browsing = pd.read_sql_query(
    "SELECT datetime(((visits.visit_time/1000000)-11644473600), 'unixepoch') AS date, urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url;",
    db,
)

browsing.set_index("date", inplace=True)
browsing.to_csv(f"{host}_{browser}_history.csv")
if os.path.exists(f"{host}_{browser}_history.csv"):
    print(f" + WROTE: {host}_{browser}_history.csv")

downloads = None
try:
    downloads = pd.read_sql_query(
        "SELECT datetime(downloads.start_time, 'unixepoch') AS date, downloads.url, downloads.full_path, downloads.received_bytes, downloads.total_bytes FROM downloads;",
        db,
    )
except:
    downloads = pd.read_sql_query(
        "SELECT datetime(((downloads.start_time/1000000)-11644473600), 'unixepoch') AS date, downloads.target_path, downloads_url_chains.url, downloads.received_bytes, downloads.total_bytes \
        FROM downloads, downloads_url_chains WHERE downloads.id = downloads_url_chains.id;",
        db,
    )

downloads.set_index("date", inplace=True)
downloads.to_csv(f"{host}_{browser}_downloads.csv")

if os.path.exists(f"{host}_{browser}_downloads.csv"):
    print(f" + WROTE: {host}_{browser}_downloads.csv")
