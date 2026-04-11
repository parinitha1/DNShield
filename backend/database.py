from pymongo import MongoClient
from backend.config import MONGO_URI, DB_NAME, COLLECTION

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION]

def insert_log(log):
    collection.insert_one(log)

def get_logs():
    return list(collection.find({}, {"_id": 0}))