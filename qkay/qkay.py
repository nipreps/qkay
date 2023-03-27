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
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
    flash,
    session,
    g,
)
from flask_login import (
    LoginManager,
    login_required,
    current_user,
    login_user,
    logout_user,
)
import json
import random
import os
from flask_login import UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mongoengine import MongoEngine
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, InputRequired, EqualTo
import sys
from index import (
    list_individual_reports,
    shuffle_reports,
    anonymize_reports,
    repeat_reports,
)
from mongoengine.queryset.visitor import Q
import numpy as np
from bs4 import BeautifulSoup
import copy
import socket

template_folder = "../"

# create the application object
app = Flask(__name__, template_folder=template_folder)

app.config["MONGODB_SETTINGS"] = {
    "db": "data_base_qkay",
    "host": "db",
    "port": 27017,
    "connect": False,

}
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
        "Repeat Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = User.objects(username=username.data).first()
        if user is not None:
            flash("Please use a different username.")


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


def patch_javascript_submit_button(
    path_html_file, username, dataset_name, report_name_original, anonymized=False
):
    """
    Modifies MRIQC widgets of a report and store the modified report in path_data

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

    html_file = open(path_html_file)
    soup = BeautifulSoup(html_file, "html.parser")
    html_file.close()
    if anonymized:
        summary_para = soup.find(id="summary")
        parent_para = summary_para.parent
        parent_para.li.extract()
        parent_para.li.extract()

        iqm_para= soup.find(id="iqms-table")
        iqm_para.decompose()

    button_container = soup.find(id="btn-post").parent
    new_button_tag = soup.new_tag("button")
    new_button_tag["class"] = "btn btn-primary"
    new_button_tag["id"] = "btn-submit"
    new_button_tag["value"] = "8sSYVI0XjFqacEMZ8wF4"
    new_button_tag["disabled"] = ""
    new_button_tag.string = "Submit"
    button_container.button.insert_after(new_button_tag)
    soup.find(id="btn-post").decompose()
    soup.find(id="btn-download").decompose()

    script_tag = soup.body.script
    with open("./scripts_js/script_button_rating_widget_template.txt", "r") as file:
        js_patch = file.read()
    h_name = socket.gethostname()
    IP_address = socket.gethostbyname(h_name)
    js_patch = js_patch.replace("IP_ADDRESS", "localhost")
    

    script_tag.string = js_patch
    if anonymized:
        path_data = (
            "./templates/templates_user_"
            + username
            + "/"
            + dataset_name
            + "_anonymized"
        )
    else:
        path_data = (
            "./templates/templates_user_"
            + username
            + "/"
            + dataset_name
            + "_non-anonymized"
        )
    if not os.path.exists(path_data):
        os.makedirs(path_data)

    with open(path_data + "/" + report_name_original, "w") as file:
        file.write(str(soup))
    return path_data


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
            print(form.password.data, file=sys.stderr)
            if user is None or not user.check_password(form.password.data):
                flash("Invalid username or password")
                return redirect(url_for("login"))
            login_user(user)
            return redirect("/" + current_user.username)
    return render_template(
        os.path.relpath("./templates/login.html", template_folder), form=form
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
                if not os.path.exists(
                    "/templates/templates_user_" + form.username.data
                ):
                    os.makedirs("./templates/templates_user_" + form.username.data)
                flash("Congratulations, you are now a registered user!")
                return redirect("/login")
            else:
                flash("Username already existing, please login")
                return redirect("/login")

    return render_template(
        os.path.relpath("./templates/register.html", template_folder), form=form
    )




@app.route("/register_new_user", methods=["POST", "GET"])
def register_new_user():
    """
    route the app to the register form page
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
                if not os.path.exists(
                    "/templates/templates_user_" + form.username.data
                ):
                    os.makedirs("./templates/templates_user_" + form.username.data)
                flash("Congratulations, you are now a registered user!")
                return redirect("/admin_panel")
            else:
                flash("Username already existing, please login")
                return redirect("/admin_panel")

    return render_template(
        os.path.relpath("./templates/register_new_user.html", template_folder), form=form
    )







@app.route("/change_pwd", methods=["POST", "GET"])
def change_psw():
    """
    route the app to the register form page
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
                    return redirect("/login")

        else:
            return redirect("/login")

    return render_template(
        os.path.relpath("./templates/change_psw.html", template_folder),
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
            return redirect("/admin_panel")
        return render_template(
            os.path.relpath("./templates/add_admin.html", template_folder),
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
            return redirect("/admin_panel")

        return render_template(
            os.path.relpath("./templates/remove_admin.html", template_folder),
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
            return redirect("/admin_panel")
        return render_template(
            os.path.relpath("./templates/remove_user.html", template_folder),
            number_users=len(list_user),
            list_users=list_user,
        )
    else:
        return redirect("/login")


@app.route("/remove_dataset", methods=["POST", "GET"])
@login_required
def remove_dataset():
    """
    route the app to the admin management page
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

            return redirect("/admin_panel")
        return render_template(
            os.path.relpath("./templates/remove_dataset.html", template_folder),
            number_dataset=len(list_dataset),
            list_dataset=list_dataset,
        )
    else:
        return redirect("/login")



@app.route("/index-<username>/A-<report_name>")
@login_required
def display_report_anonymized(username, report_name):
    """
    display anonymized report A-<report_name>
    """
    dataset_name = report_name.split("_")[0]
    current_inspection = Inspection.objects(
        Q(dataset=dataset_name) & Q(username=username)
    )
    anonymized_names = current_inspection.values_list("names_anonymized")
    original_names = current_inspection.values_list("names_shuffled")
    ind_name = np.where(np.array(anonymized_names[0]) == "A-" + report_name)
    report_name_original = np.array(original_names[0])[ind_name][0]
    dataset_path = str(
        Dataset.objects(name=dataset_name).values_list("path_dataset")[0]
    )
    path_templates_mriqc = dataset_path + report_name_original
    path_anonymized_data = patch_javascript_submit_button(
        path_templates_mriqc,
        username,
        dataset_name,
        report_name_original,
        anonymized=True,
    )
    return render_template(
        os.path.relpath(
            path_anonymized_data + "/" + report_name_original, template_folder
        )
    )


@app.route("/index-<username>/sub-<report_name>")
@login_required
def display_report_non_anonymized(username, report_name):
    """
    display report sub-<subject_number>
    """
    user = User.objects(username=username).first()
    dataset = user.current_dataset
    dataset_path = str(Dataset.objects(name=dataset).values_list("path_dataset")[0])

    path_templates_mriqc = dataset_path + "sub-" + report_name
    path_modified_template = patch_javascript_submit_button(
        path_templates_mriqc, username, dataset, "sub-" + report_name, anonymized=False
    )
    return render_template(
        os.path.relpath(path_modified_template + "/sub-" + report_name, template_folder)
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
            os.path.relpath(
                "./templates/user_panel_admin_version.html", template_folder
            ),
            list_inspections_assigned=list_inspections_assigned,
            number_inspections=len(list_inspections_assigned),
            username=username,
            route_list=route_list,
        )
    else:
        return render_template(
            os.path.relpath("./templates/user_panel.html", template_folder),
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
    current_inspection = Inspection.objects(Q(dataset=dataset) & Q(username=username))
    array_rated = (
        np.array(
            current_inspection.values_list("index_rated_reports")[0], dtype=np.int8
        )
        + 0
    ).tolist()
    names_files = current_inspection.values_list("names_anonymized")[0]
    return render_template(
        os.path.relpath(path_index, template_folder),
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
        if request.method == "POST":
            pass
        return render_template(
            os.path.relpath("./templates/admin_panel.html", template_folder),
            number_users=len(list_users),
            list_users=list_users,
            list_admin=list_admin,
            number_admin=len(list_admin),
            number_datasets=len(list_datasets),
            list_datasets=list_datasets,
        )
    else:
        return redirect("/login")


@app.route("/create_dataset", methods=["POST", "GET"])
def create_dataset():
    """
    Create a Dataset object with the parameters given in the form
    """
    if request.method == "POST":
        dataset_name = request.form["name"]
        dataset_path = request.form["path"]
        try:
            secondfile=os.listdir(dataset_path)[1]
            dataset = Dataset(name=dataset_name, path_dataset=dataset_path)
            dataset.save()
            return redirect("/admin_panel")
        except:
            return redirect("/empty_dataset")


    return render_template(
        os.path.relpath("./templates/create_dataset.html", template_folder)
    )

@app.route("/empty_dataset", methods=["POST", "GET"])
@login_required
def empty_dataset():
    """
    display an error message when the dataset is empty
    """
    return render_template(
        os.path.relpath("./templates/error_empty_dataset.html", template_folder)
    )


@app.route("/assign_dataset", methods=["POST", "GET"])
def assign_dataset():
    """
    Assign a dataset to a user
    """
    list_users = User.objects.all().values_list("username")
    list_datasets = Dataset.objects.all().values_list("name")
    if request.method == "POST":
        dataset_selected = list_datasets[int(request.form.get("datasets dropdown"))]
        username = list_users[int(request.form.get("users dropdown"))]
        randomize = request.form.get("option_randomize")
        rate_all = request.form.get("option_rate_all")
        blind = request.form.get("option_blind")
        random_seed = random.randint(0, 100000)
        dataset_path = str(
            Dataset.objects(name=dataset_selected).values_list("path_dataset")[0]
        )

        names_files = list_individual_reports(dataset_path)
        new_names = names_files
        if rate_all:
            names_repeated=repeat_reports(new_names,40)
        else:
            names_repeated=names_files
        if randomize:
            names_shuffled = shuffle_reports(names_repeated, random_seed)
        else:
            names_shuffled = names_repeated
        if blind:
            names_anonymized = anonymize_reports(names_repeated, dataset_selected)
        else:
            names_anonymized = names_repeated

        names_subsample=names_repeated

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
        return redirect("/admin_panel")

    return render_template(
        os.path.relpath("./templates/assign_dataset.html", template_folder),
        number_users=len(list_users),
        list_users=list_users,
        number_datasets=len(list_datasets),
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

    report = Rating()
    report = report.from_json(json.dumps(request_data))
    report.dataset = dataset
    report.rater_id = username
    report.save()
    current_inspection = Inspection.objects(Q(dataset=dataset) & Q(username=username))
    index_rated = np.array(current_inspection.values_list("index_rated_reports"))
    shuffled_names = current_inspection.values_list("names_shuffled")
    ind_name = np.where(np.array(shuffled_names[0]) == str(report.subject) + ".html")
    index_rated[0][ind_name] = True
    current_inspection.update_one(set__index_rated_reports=index_rated[0].tolist())
    return redirect("/index-" + username + "/" + dataset, code=307)


if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.run(debug=True, host="0.0.0.0", port=5000)
