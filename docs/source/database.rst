Accessing MongoDB Database
==========================

Introduction
------------

This document provides instructions on how to access the MongoDB database used in qkay. There are two main methods outlined below: accessing it using MongoDB Compass and accessing it in Python code.

Accessing with MongoDB Compass
------------------------------

To access the MongoDB database used in qkay using MongoDB Compass, follow these steps:

1. Open MongoDB Compass on your local machine. If needed, you can find the instructions to install MongoDB Compass `here <https://www.mongodb.com/docs/compass/current/install/>`_.

2. Click on the "New Connection" button.

3. In the "New Connection" dialog, enter the connection URI. If you are using Docker to run qkay, the URI should typically be `mongodb://localhost:27017`. Ensure that the database is running when you try to access it.

4. Click on the "Connect" button.

5. Once connected, you will see a list of databases. Look for the database named `data_base_qkay` and click on it to access its collections and documents.

Accessing in Python script
--------------------------

To access the MongoDB database used in qkay in a Python script, you can use the pymongo library. Make sure you have pymongo installed in your Python environment. Here's a sample Python code snippet to connect to the database:

    .. code-block:: python

        from pymongo import MongoClient

        # Connect to MongoDB
        client = MongoClient('mongodb://localhost:27017/')

        # Access the database
        db = client['data_base_qkay']

        # Now you can work with the database, for example:
        # Access the ratings collection
        collection = db['ratings']

        # Query all ratings
        ratings = collection.find({})

        # Iterate over ratings
        for rating in ratings:
            print(rating)
