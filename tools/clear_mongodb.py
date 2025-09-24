import os

from pymongo import MongoClient

client = MongoClient(os.environ["MONGODB"])["decompile"]
collections = client.list_collection_names()
for c in collections:
    client.drop_collection(c)
