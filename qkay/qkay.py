#!/usr/bin/env python3
# Copyright 2023 The NiPreps Developers <nipreps@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# We support and encourage derived works from this project, please read
# about our expectations at
#
#     https://www.nipreps.org/community/licensing/
#
import base64
import glob
import json
import os
import random

import numpy as np
import os.path as op
from bs4 import BeautifulSoup
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_mongoengine import MongoEngine
from flask_wtf import FlaskForm
from index import (
    anonymize_reports,
    list_individual_reports,
    repeat_reports,
    shuffle_reports,
)
from logging.config import dictConfig
from mongoengine.queryset.visitor import Q
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo


dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
            }
        },
        "root": {"level": "DEBUG", "handlers": ["wsgi"]},
    }
)

template_folder = "../"

# create the application object
app = Flask(__name__, template_folder=template_folder)

app.config["MONGODB_SETTINGS"] = {
    "db": "data_base_qkay",
    "host": "db",
    "port": 27017,
    "connect": False,
}
app.logger.info(f"MONGODB_SETTINGS: {app.config['MONGODB_SETTINGS']}")
app.config.update(SECRET_KEY=os.urandom(24))
db = MongoEngine()
db.init_app(app)

# Binds the app with the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Document):
    """
    Class to store users info

    ...

    Attributes
    ----------

    meta : dict
        mongodb collection
    username : str
        name of the user
    password : str
        hashed password
    is admin : bool
        True if the user as admin privileges
    dataset_list : string list
        list of datasets assigned to the users
    current_dataset : string
        dataset currently inspected by the user

    Methods
    -------
    set_password(password)
        Hash the user password with the method pbkdf2:sha1, salt it with a string length 8 and stores it.
    check_password(password)
        checks the password against the salted and hashed password value
    """

    username = db.StringField()
    password = db.StringField()
    is_admin = db.BooleanField(default=False)
    dataset_list = db.ListField()
    current_dataset = db.StringField()
    meta = {"collection": "users"}

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Dataset(db.Document):
    """
    Class to store datasets info

    ...

    Attributes
    ----------
    meta : dict
        mongodb collection
    name : str
        name of the dataset
    path_dataset : str
        path to the dataset
    """

    meta = {"collection": "datasets"}
    name = db.StringField()
    path_dataset = db.StringField()

    def validate_dataset(self):
        """
        Validate if the dataset directory exists and contains HTML files.
        """
        # Check whether the folder contains at least one HTML file
        for _, _, files in os.walk(self.path_dataset):
            for file in files:
                if file.endswith(".html"):
                    return True

        return op.exists(self.path_dataset) and any(
            file.endswith(".html") for _, _, file in os.walk(self.path_dataset)
        )


class Inspection(db.Document):
    """
        Class to define an inspection
        ...

        Attributes
        ----------
    git rebase --abort
        meta : dict
            mongodb collection
        dataset : str
            name of the dataset to be inspected
        username : str
            name of the user assigned to the inspection
        randomize : bool
            If files must be shuffled
        rate_all : bool
            If all files must be rated
        blind : bool
            If reports must be anonymized
        names_files : string list
            list of filenames to grade
        names_shuffled : string list
            shuffled list of filenames
        names_anonymized : string list
            list of filenames anonymized and shuffled if randomize==True
        names_subsample: string list
            subsample of file to inspect if rate_all==False
        random_seed: int
            random seed used to shuffle the filename
        index_rated_reports: list
            index of reports already rated
    """

    meta = {"collection": "inspections"}
    dataset = db.StringField()
    username = db.StringField()
    randomize = db.BooleanField(default=False)
    rate_all = db.BooleanField(default=False)
    blind = db.BooleanField(default=False)
    names_files = db.ListField()
    names_shuffled = db.ListField()
    names_anonymized = db.ListField()
    names_subsample = db.ListField()
    random_seed = db.IntField()
    index_rated_reports = db.ListField()


class Rating(db.Document):
    """
    Class to define an inspection
    ...

    Attributes
    ----------

    meta : dict
        mongodb collection
    dataset : str
        name of the dataset to be inspected
    username : str
        name of the user assigned to the inspection
    randomize : bool
        If files must be shuffled
    rate_all : bool
        If all files must be rated
    blind : bool
        If reports must be anonymized
    names_files : string list
        list of filenames to grade
    names_shuffled : string list
        shuffled list of filenames
    names_anonymized : string list
        list of filenames anonymized and shuffled if randomize==True
    names_subsample: string list
        subsample of file to inspect if rate_all==False
    random_seed: int
        random seed used to shuffle the filename
    index_rated_reports: list
        index of reports already rated
    """

    meta = {"collection": "ratings"}
    name = db.StringField()
    md5sum = db.StringField()
    rater_id = db.StringField()
    dataset = db.StringField()
    subject = db.StringField()
    rating = db.FloatField()
    artifacts = db.StringField()
    time_sec = db.FloatField()
    confidence = db.FloatField()
    comment = db.StringField()
    comments = db.StringField()


class LoginForm(FlaskForm):
    """
    Form for login
    """

    username = StringField("username")
    password = PasswordField("password")
    submit = SubmitField("submit")


class RegistrationForm(FlaskForm):
    """
    Form for registration
    """

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    password2 = PasswordField(
        "Repeat Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords do not match"),
        ],
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = User.objects(username=username.data).first()
        if user is not None:
            app.logger.error("User %s already exists", user.username)
            flash("Username already exists.", "error")


class ChangepswForm(FlaskForm):
    """
    Form for password change
    """

    old_password = PasswordField("Old password", validators=[DataRequired()])
    password = PasswordField("New password", validators=[DataRequired()])
    password2 = PasswordField(
        "Repeat new password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Change password")


def modify_mriqc_report(
    path_html_file,
):
    """
    Modify the MRIQC report and its rating widget.
    Deletes the IQMs section.
    Replace in the rating widget the download button by a submit button that is disabled for a set amount of time to enforce minimum rating time.

    Parameters
    ---------
    path_html_file : str
        path of report to modify
    username : str
        name of current user
    dataset_name : str
        name of current dataset
    report_name_original:str
        name of the report to modify
    anonymized : bool
        True if filenames must be hidden


    Returns
    -------
    path to the new report
    """
    with open(path_html_file, "r") as file:
        html_file = file.read()
    soup = BeautifulSoup(html_file, "html.parser")

    # if subject is unspecified, replace it by the report name
    script_tag = soup.find(
        "script", string=lambda text: text and 'var sub = "unspecified";' in text
    )
    if script_tag:
        report_name = op.basename(path_html_file)
        script_tag.string = script_tag.string.replace(
            'var sub = "unspecified";',
            f'var sub = "{report_name.replace(".html", "")}";',
        )

    # Embed the SVG images in the HTML files otherwise they are not displayed
    svg_tags = soup.find_all("img", {"src": lambda src: src.endswith(".svg")})
    original_work_dir = os.getcwd()
    html_file_dir = op.dirname(path_html_file)
    os.chdir(html_file_dir)
    for svg in svg_tags:
        # Open the SVG file and read its contents
        with open(svg["src"], "rb") as file:
            svg_data = file.read()

        # Convert the SVG data to base64 encoding
        base64_data = base64.b64encode(svg_data).decode("utf-8")

        # Replace the SVG source with the base64-encoded data
        svg["src"] = "data:image/svg+xml;base64," + base64_data
    os.chdir(original_work_dir)

    # Remove Reproducibility and provenance information section to remove access to the IQMs
    iqms_section = soup.find("h2", id="about-metadata-2")
    iqms_section.decompose()

    # Replace the download button by a submit button
    button_container = soup.find(id="btn-download").parent
    new_button_tag = soup.new_tag("button")
    new_button_tag["class"] = "btn btn-primary"
    new_button_tag["id"] = "btn-submit"
    new_button_tag["value"] = "8sSYVI0XjFqacEMZ8wF4"
    new_button_tag["disabled"] = ""
    new_button_tag.string = "Submit"
    button_container.append(new_button_tag)
    button_post = soup.find(id="btn-post")
    if button_post:
        button_post.decompose()
    soup.find(id="btn-download").decompose()

    # Define the behavior of clicking on the submit button
    # Notably, disable submit button for a set amount of time
    # It enforces the raters to spend at least that time to assign a quality rating
    script_tag = soup.body.script
    with open(
        "./scripts_js/script_button_rating_widget_template_minimum_time.txt", "r"
    ) as file:
        js_patch = file.read()
    js_patch = js_patch.replace("IP_ADDRESS", "localhost")
    script_tag.string = js_patch

    modified_mriqc_report = str(soup)
    return modified_mriqc_report


@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    route the app to the login page
    """

    form = LoginForm()
    if not User.objects(Q(is_admin=True)).values_list("username"):
        if not User.objects(Q(username="Admin")).values_list("username"):
            admin = User(
                username="Admin",
                password=generate_password_hash("abcd"),
                is_admin=True,
            )
            admin.save()
    else:
        admin = User.objects(username="Admin").first()
        admin.is_admin = True
        admin.save()

    if current_user.is_authenticated:
        return redirect("/" + current_user.username)
    if request.method == "POST":
        if current_user.is_authenticated:
            return redirect("/" + current_user.username)

        if form.validate_on_submit():
            user = User.objects(username=form.username.data).first()
            if user is None or not user.check_password(form.password.data):
                app.logger.error("Invalid username or password")
                flash("Invalid username or password")
                return redirect(url_for("login"))
            login_user(user)
            return redirect("/" + current_user.username)
    return render_template(
        op.relpath("./templates/login.html", template_folder), form=form
    )


@app.route("/register", methods=["POST", "GET"])
def register():
    """
    route the app to the register form page
    """

    form = RegistrationForm()
    if current_user.is_authenticated:
        logout_user()

    if request.method == "POST":
        if form.validate_on_submit():
            user_with_same_username = User.objects(username=form.username.data).first()
            if not user_with_same_username:
                user = User(
                    username=form.username.data,
                    password=generate_password_hash(form.password.data),
                )
                user.save()
                app.logger.info("User %s registered", user.username)
                return redirect("/login")
            else:
                flash("Please login.", "error")
                return redirect("/login")

    return render_template(
        op.relpath("./templates/register.html", template_folder), form=form
    )


@app.route("/register_new_user", methods=["POST", "GET"])
def register_new_user():
    """
    route the app to the page to register a new user
    """

    form = RegistrationForm()

    if request.method == "POST":
        if form.validate_on_submit():
            user_with_same_username = User.objects(username=form.username.data).first()
            if not user_with_same_username:
                user = User(
                    username=form.username.data,
                    password=generate_password_hash(form.password.data),
                )
                user.save()
                return redirect("/admin_panel")
            else:
                # Clear the form to remove the entered username and password
                form.username.data = ""
                form.password.data = ""
                flash("Please use a different username.", "error")
                return render_template(
                    op.relpath("./templates/register_new_user.html", template_folder),
                    form=form,
                )

    return render_template(
        op.relpath("./templates/register_new_user.html", template_folder),
        form=form,
    )


@app.route("/change_pwd", methods=["POST", "GET"])
def change_psw():
    """
    route the app to the page to change password
    """

    form = ChangepswForm()
    username_1 = current_user.username
    if request.method == "POST":
        if current_user.is_authenticated:
            if form.validate_on_submit():
                if current_user.check_password(form.old_password.data):
                    user = User.objects(Q(username=current_user.username))
                    user.update_one(
                        set__password=generate_password_hash(form.password.data)
                    )
                    app.logger.info("Password changed")
                    return redirect("/login")

        else:
            return redirect("/login")

    return render_template(
        op.relpath("./templates/change_psw.html", template_folder),
        form=form,
        username=username_1,
    )


@app.route("/logout")
def logout():
    """
    logout the user and redirect to the login page
    """
    logout_user()
    return redirect("/login")


@app.route("/add_admin", methods=["POST", "GET"])
@login_required
def add_admin():
    """
    route the app to the admin management page
    """
    if current_user.is_admin:
        list_users = User.objects.all().values_list("username")
        if request.method == "POST":
            username_selected = list_users[int(request.form.get("users dropdown"))]
            user = User.objects(Q(username=username_selected))
            user.update_one(set__is_admin=True)
            app.logger.info("User %s is now an admin", user.username)
            return redirect("/admin_panel")
        return render_template(
            op.relpath("./templates/add_admin.html", template_folder),
            number_users=len(list_users),
            list_users=list_users,
        )
    else:
        return redirect("/login")


@app.route("/remove_admin", methods=["POST", "GET"])
@login_required
def remove_admin():
    """
    route the app to the admin management page
    """
    if current_user.is_admin:
        list_admin = User.objects(Q(is_admin=True)).values_list("username")
        if request.method == "POST":
            username_selected = list_admin[int(request.form.get("users dropdown"))]
            user = User.objects(Q(username=username_selected))
            user.update_one(set__is_admin=False)
            app.logger.info("User %s is no longer an admin", user.username)
            return redirect("/admin_panel")

        return render_template(
            op.relpath("./templates/remove_admin.html", template_folder),
            number_users=len(list_admin),
            list_users=list_admin,
        )
    else:
        return redirect("/login")


@app.route("/remove_user", methods=["POST", "GET"])
@login_required
def remove_user():
    """
    route the app to the admin management page
    """
    if current_user.is_admin:
        list_user = User.objects.all().values_list("username")
        if request.method == "POST":
            username_selected = list_user[int(request.form.get("users dropdown"))]
            user = User.objects(Q(username=username_selected))
            user.delete()
            app.logger.info("User %s has been deleted", username_selected)
            return redirect("/admin_panel")
        return render_template(
            op.relpath("./templates/remove_user.html", template_folder),
            number_users=len(list_user),
            list_users=list_user,
        )
    else:
        return redirect("/login")


@app.route("/remove_dataset", methods=["POST", "GET"])
@login_required
def remove_dataset():
    """
    route the app to the remove dataset page
    """
    if current_user.is_admin:
        list_dataset = Dataset.objects.all().values_list("name")
        if request.method == "POST":
            name_selected = list_dataset[int(request.form.get("users dropdown"))]
            dataset = Dataset.objects(Q(name=name_selected))
            dataset.delete()
            inspections = Inspection.objects(Q(dataset=name_selected))
            for inspection in inspections:
                inspection.delete()
            app.logger.info("Dataset %s has been deleted", name_selected)
            return redirect("/admin_panel")
        return render_template(
            op.relpath("./templates/remove_dataset.html", template_folder),
            number_dataset=len(list_dataset),
            list_dataset=list_dataset,
        )
    else:
        return redirect("/login")


@app.route("/remove_inspection", methods=["POST", "GET"])
@login_required
def remove_inspection():
    """
    route the app to the remove inspection page
    """
    if current_user.is_admin:
        list_inspection_username = Inspection.objects.all().values_list("username")
        list_inspection_dataset = Inspection.objects.all().values_list("dataset")
        list_inspection_id = Inspection.objects.all().values_list("id")
        if request.method == "POST":
            id_selected = list_inspection_id[int(request.form.get("users dropdown"))]
            inspection = Inspection.objects(Q(id=id_selected))
            inspection.delete()
            app.logger.info("Inspection %s has been deleted", id_selected)
            return redirect("/admin_panel")

        return render_template(
            op.relpath("./templates/remove_inspection.html", template_folder),
            number_inspection=len(list_inspection_username),
            list_username=list_inspection_username,
            list_dataset=list_inspection_dataset,
        )
    else:
        return redirect("/login")


@app.route("/index-<username>/sub-<report_name>")
@login_required
def display_report_non_anonymized(username, report_name):
    """
    display report sub-<subject_number>
    """
    user = User.objects(username=username).first()
    dataset = user.current_dataset
    dataset_path = str(Dataset.objects(name=dataset).values_list("path_dataset")[0])

    app.logger.debug("Searching recursively for a report named %s under %s.", report_name, dataset_path)

    mriqc_report = ""
    path_mriqc_report = glob.glob(os.path.join(dataset_path, "**", "sub-" + report_name), recursive=True)
    if len(path_mriqc_report) == 0:
        app.logger.error("No report named %s was found in the children of %s.","sub-" + report_name, dataset_path)
    else:
        path_mriqc_report = path_mriqc_report[0]
        # Modify the html to adapt it to Q'kay    
        mriqc_report = modify_mriqc_report(path_mriqc_report)

    return render_template(
        op.relpath("./templates/report.html", template_folder),
        html_content=mriqc_report,
    )


@app.route("/")
@login_required
def home():
    """
    display home page
    """
    return redirect("/login")


@app.route("/<username>")
@login_required
def info_user(username):
    """
    display user's panel
    """
    list_inspections_assigned = Inspection.objects(username=username).values_list(
        "dataset"
    )
    route_list = [
        "/index-" + username + "/" + str(name) for name in list_inspections_assigned
    ]

    if request.method == "POST":
        pass
    if current_user.is_admin:
        return render_template(
            op.relpath("./templates/user_panel_admin_version.html", template_folder),
            list_inspections_assigned=list_inspections_assigned,
            number_inspections=len(list_inspections_assigned),
            username=username,
            route_list=route_list,
        )
    else:
        return render_template(
            op.relpath("./templates/user_panel.html", template_folder),
            list_inspections_assigned=list_inspections_assigned,
            number_inspections=len(list_inspections_assigned),
            username=username,
            route_list=route_list,
        )


@app.route("/index-<username>/<dataset>", methods=["POST", "GET"])
@login_required
def display_index_inspection(username, dataset):
    """
    display interactive list of files to grade
    """
    user = User.objects(username=username).first()
    user.current_dataset = dataset
    user.save()
    path_index = "./templates/index.html"

    app.logger.debug("Searching for inspection matching dataset %s and username %s.", dataset, username)

    # Find in the inspection which reports have been rated
    current_inspection = Inspection.objects(Q(dataset=dataset) & Q(username=username))
    array_rated = (
        np.array(
            current_inspection.values_list("index_rated_reports")[0], dtype=np.int8
        )
        + 0
    ).tolist()
    names_files = current_inspection.values_list("names_anonymized")[0]
    app.logger.debug("%i files found to rate.", len(names_files))

    return render_template(
        op.relpath(path_index, template_folder),
        array_rated=array_rated,
        index_list=names_files,
        url_index="/index-" + str(username) + "/" + str(dataset),
        url_home="/" + str(username),
    )


@app.route("/admin_panel", methods=["POST", "GET"])
@login_required
def admin_panel():
    """
    display admin panel
    """

    if current_user.is_admin:
        list_users = User.objects.all().values_list("username")
        list_datasets = Dataset.objects.all().values_list("name")
        list_admin = User.objects(Q(is_admin=True)).values_list("username")
        list_inspection = [
            f"{inspection.dataset} -> {inspection.username}"
            for inspection in Inspection.objects.all()
        ]
        if request.method == "POST":
            pass
        return render_template(
            op.relpath("./templates/admin_panel.html", template_folder),
            list_users=list_users,
            list_admin=list_admin,
            list_datasets=list_datasets,
            list_inspection=list_inspection,
        )
    else:
        return redirect("/login")


@app.route("/create_dataset", methods=["POST", "GET"])
def create_dataset():
    """
    Create a Dataset object with the parameters given in the form
    """
    if request.method == "POST":
        selected_datasets = request.form.getlist("datasets[]")
        for d in selected_datasets:
            dataset_path = op.join("/datasets", d)
            app.logger.debug("Searching recursively for dataset_description.json under %s.", dataset_path) 

            # Get dataset name from the data_description.json file if it exists
            # otherwise, use the folder name
            desc_file = ""
            desc_files = glob.glob(os.path.join(dataset_path, "**", "dataset_description.json"), recursive=True)
            if len(desc_files) > 1:
                app.logger.warning("More than one dataset_description.json was found!: %s .", desc_files) 
            
            desc_file = desc_files[0]
            app.logger.debug("dataset_description.json found at %s.", desc_file) 
            if desc_file:
                with open(desc_file, "r") as file:
                    data_description = json.load(file)
                    dataset_name = data_description["Name"]
                    app.logger.info("The dataset name %s was assigned based on the name in %s", dataset_name, desc_file) 
                # If the name of the dataset is the default MRIQC value, use the folder name instead
                if dataset_name == "MRIQC - MRI Quality Control":
                    app.logger.info("The dataset name is the default of MRIQC which is not informative, using folder name instead: %s.", d) 
                    dataset_name = d
            else:
                app.logger.info("No dataset_description.json found, assigning dataset name to folder name: %s.", d) 
                dataset_name = d

            dataset = Dataset(name=dataset_name, path_dataset=dataset_path)
            existing_dataset = Dataset.objects(name=dataset_name).first()
            if not dataset.validate_dataset():
                app.logger.error(
                    "The directory %s does not exist or does not contain any HTML files.",
                    dataset_path,
                )
                flash(
                    "The directory %s does not exist or does not contain any HTML files. Please select another dataset."
                    % dataset_path,
                    "error",
                )
                return redirect("/create_dataset")
            elif existing_dataset:
                app.logger.error("The dataset %s already exists.", dataset_name)
                flash(
                    "The dataset %s already exists. Please select another dataset."
                    % dataset_name,
                    "error",
                )
                return redirect("/create_dataset")
            else:
                dataset.save()
                app.logger.info(
                    "New dataset named %s created from %s.", dataset_name, dataset_path
                )

        return redirect("/admin_panel")

    # Extract the list of folders under the directory /datasets
    datasets = [
        folder
        for folder in os.listdir("/datasets")
        if op.isdir(op.join("/datasets", folder))
    ]
    app.logger.debug("List of folders under /datasets: %s", datasets)
    return render_template(
        op.relpath("./templates/create_dataset.html", template_folder),
        datasets=datasets,
    )


@app.route("/assign_dataset", methods=["POST", "GET"])
def assign_dataset():
    """
    Assign a dataset to a user
    """
    list_users = User.objects.all().values_list("username")
    list_datasets = Dataset.objects.all().values_list("name")
    if request.method == "POST":
        dataset_selected = request.form.get("datasets dropdown")
        app.logger.debug("Dataset %s selected for inspection", dataset_selected)
        username = request.form.get("users dropdown")
        app.logger.debug("User %s selected for inspection", username)
        randomize = request.form.get("option_randomize")
        rate_all = request.form.get("option_rate_all")
        blind = request.form.get("option_blind")
        two_datasets = request.form.get("option_two_datasets")
        random_seed = random.randint(0, 100000)
        dataset_path = str(
            Dataset.objects(name=dataset_selected).values_list("path_dataset")[0]
        )

        names_files = list_individual_reports(dataset_path, two_folders=two_datasets)
        app.logger.debug(
            "%s reports found at %s", len(names_files), dataset_path
        )
        new_names = names_files
        if rate_all:
            names_repeated = repeat_reports(new_names, 40, two_folders=two_datasets)
        else:
            names_repeated = names_files
        if randomize:
            names_shuffled = shuffle_reports(names_repeated, random_seed)
        else:
            names_shuffled = names_repeated
        if blind:
            names_anonymized = anonymize_reports(names_repeated, dataset_selected)
        else:
            names_anonymized = names_repeated

        names_subsample = names_repeated

        index_rated_reports = [False] * len(names_files)

        inspection = Inspection(
            dataset=dataset_selected,
            username=username,
            randomize=randomize,
            blind=blind,
            rate_all=rate_all,
            names_files=names_files,
            names_shuffled=names_shuffled,
            names_anonymized=names_anonymized,
            names_subsample=names_subsample,
            random_seed=random_seed,
            index_rated_reports=index_rated_reports,
        )
        inspection.save()
        app.logger.info(
            "Dataset %s has been assigned for inspection to user %s.",
            dataset_selected,
            username,
        )
        return redirect("/admin_panel")

    return render_template(
        op.relpath("./templates/assign_dataset.html", template_folder),
        list_users=list_users,
        list_datasets=list_datasets,
    )


@app.route("/receive_rating", methods=["POST"])
@login_required
def receive_report():
    """
    Save the rated reports in the database
    """
    request_data = request.get_json()
    username = current_user.username
    dataset = current_user.current_dataset
    current_inspection = Inspection.objects(Q(dataset=dataset) & Q(username=username))
    shuffled_names = current_inspection.values_list("names_shuffled")
    index_rated = np.array(current_inspection.values_list("index_rated_reports"))
    report = Rating()
    report = report.from_json(json.dumps(request_data))
    report.dataset = dataset
    report.rater_id = username
    report.save()
    ind_name = np.where(np.array(shuffled_names[0]) == str(report.subject) + ".html")
    index_rated[0][ind_name] = True
    current_inspection.update_one(set__index_rated_reports=index_rated[0].tolist())
    app.logger.info("Report %s has been rated by user %s.", report.subject, username)
    return redirect("/index-" + username + "/" + dataset, code=307)


if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.run(debug=True, host="0.0.0.0", port=5000)
