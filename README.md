# Introduction
Qkay is a Docker containerized web application developed using Flask, which serves as a manager for the quality assessment of large neuroimaging studies.

# Prerequisites
To run the Qkay package using Docker Compose, you'll need to have Docker and Docker Compose installed on your machine. You can download and install them from the following links:
[Docker](https://docs.docker.com/get-docker/)
[Docker-compose](https://docs.docker.com/compose/install/)
# Usage
Before using qkay, you will need to set up the necessary environment variables by completing the .env file. In this file, you should provide the path to the database and the path to all datasets that you want to use. If there is more than one dataset, the path should be the parent folder.

Run the containers with Docker Compose:
```
$ docker-compose up
```
The application will be reachable on  http://localhost.
Here are the steps you need to follow to set up the environment variables:

    1. Open the .env file in a text editor.
    2. Set the `DB_PATH` variable to the directory where MongoDB should store its data.
    3. Set the `DATASETS_PATH` variable to the path of the folder containing all the datasets you want to use. If you have more than one dataset, provide the path to the parent folder.
    4. Save the .env file.

To run qkay using Docker Compose, follow these steps:

    1. Clone the qkay repository from GitHub: git clone https://github.com/nipreps/qkay.git
    2. Navigate to the qkay directory: cd qkay
    3. Run "docker-compose up" to start the app and the database.
    4. Open a web browser and navigate to https://localhost.
    5. Log in to the app using the following credentials:
        Username: Admin
        Password: abcd
    6. Once you have logged in, go to the Admin panel and change your password to something more secure.
    7. Once you have logged in, go to the Admin panel and add a dataset by clicking on the "Add Dataset" button. You will find the list of all datasets in the folder indicated in the .env file. Select the dataset you want to add.

# Python package
Qkay is organized as a Python package. External scripts can import the Flask
application directly with:

```python
from qkay import app
```

# Contributing
We welcome contributions to Qkay. Please read the [contributing guide](https://www.nipreps.org/community/CONTRIBUTING/) to get started.
# License
Qkay is released under the Apache 2.0 License.
