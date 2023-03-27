# Introduction
Qkay is a Docker containerized web application developed using Flask, which serves as a manager for the quality assessment of large neuroimaging studies.

# Prerequisites
To run the Qkay package using Docker Compose, you'll need to have Docker and Docker Compose installed on your machine. You can download and install them from the following links:
[Docker](https://docs.docker.com/get-docker/)
[Docker-compose](https://docs.docker.com/compose/install/)
# Usage
The file .env must be updated with the path to the MongoDB database and the path to the folder containing all datasets before running the application.

Run the containers with Docker Compose:
```
$ docker-compose up
```
The application will be reachable on  http://localhost.

# Contributing
We welcome contributions to Qkay. Please read the [contributing guide](https://github.com/nipreps/qkay/blob/docker-version/CONTRIBUTING.md) to get started.
# License
Qkay is released under the MIT License.
